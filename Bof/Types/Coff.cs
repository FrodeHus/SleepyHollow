using System.Runtime.InteropServices;

namespace SleepyHollow.Bof.Types;

/// <summary>
/// Represents a COFF (Common Object File Format) loader and executor for BOF modules.
/// </summary>
internal class Coff
{
    #region Fields
    private readonly ImageFileHeader _fileHeader;
    private readonly List<ImageSectionHeader> _sectionHeaders = [];
    private readonly List<ImageSymbol> _symbols = [];
    private readonly long _stringTableOffset;
    private readonly byte[] _bofBytes;
    private readonly string _importPrefix;
    private readonly IntPtr _baseAddress;
    private readonly uint _totalMemoryAllocated;
    private IntPtr[] _sectionAddresses = [];
    private readonly ImportAddressTable _importAddressTable = new();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void GoDelegate();
    #endregion

    #region Constructor
    /// <summary>
    /// Loads and prepares a COFF/BOF image from the provided byte array.
    /// </summary>
    public Coff(byte[] bofBytes)
    {
        if (bofBytes == null || bofBytes.Length < Marshal.SizeOf<ImageFileHeader>())
            throw new ArgumentException("Invalid BOF bytes provided.");

        _bofBytes = bofBytes;

        _fileHeader = Deserialize<ImageFileHeader>(bofBytes[0..Marshal.SizeOf<ImageFileHeader>()]);
        _importPrefix = _fileHeader.Machine == ImageFileMachine.IMAGE_FILE_MACHINE_AMD64 ? "__imp_" : "__imp__";
        _stringTableOffset = _fileHeader.PointerToSymbolTable + (_fileHeader.NumberOfSymbols * Marshal.SizeOf<ImageSymbol>());

        ReadSectionHeaders(bofBytes);
        ReadSymbols(bofBytes);
        ValidateHeaderCounts();

        (_baseAddress, _totalMemoryAllocated) = WriteSectionsToMemory();
        SetBOFVariables();
        ResolveAllRelocations();
        var entryAddress = ResolveEntryPoint("go");
        SetPermissionsForSections();
        try
        {
            ExecuteEntryPoint(entryAddress);
        }
        finally
        {
            Clear();
        }
    }
    #endregion

    #region Section & Symbol Reading
    private void ReadSectionHeaders(byte[] bofBytes)
    {
        int sectionHeadersOffset = Marshal.SizeOf<ImageFileHeader>();
        for (int i = 0; i < _fileHeader.NumberOfSections; i++)
        {
            var sectionHeader = Deserialize<ImageSectionHeader>(bofBytes.AsSpan(sectionHeadersOffset + (i * Marshal.SizeOf<ImageSectionHeader>()), Marshal.SizeOf<ImageSectionHeader>()).ToArray());
            _sectionHeaders.Add(sectionHeader);
        }
        _sectionAddresses = new IntPtr[_sectionHeaders.Count];
    }

    private void ReadSymbols(byte[] bofBytes)
    {
        for (int i = 0; i < _fileHeader.NumberOfSymbols; i++)
        {
            var symbol = Deserialize<ImageSymbol>(
                bofBytes.AsSpan((int)_fileHeader.PointerToSymbolTable + (i * Marshal.SizeOf<ImageSymbol>()), Marshal.SizeOf<ImageSymbol>()).ToArray());
            _symbols.Add(symbol);
        }
    }

    private void ValidateHeaderCounts()
    {
        if (_symbols.Count != _fileHeader.NumberOfSymbols)
            throw new InvalidOperationException("Number of symbols does not match the expected count in the file header.");
        if (_sectionHeaders.Count != _fileHeader.NumberOfSections)
            throw new InvalidOperationException("Number of section headers does not match the expected count in the file header.");
    }
    #endregion

    #region Memory Management
    private (nint baseAddress, uint totalMemoryAllocated) WriteSectionsToMemory()
    {
        int totalPages = _sectionHeaders.Sum(sectionHeader =>
            sectionHeader.SizeOfRawData == 0 ? 0 : (int)((sectionHeader.SizeOfRawData + Environment.SystemPageSize - 1) / Environment.SystemPageSize));
        int totalMemoryToAllocate = totalPages * Environment.SystemPageSize;
        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine($"Total memory to allocate: {totalMemoryToAllocate}");

        var address = Lib.VirtualAlloc(
            IntPtr.Zero,
            (uint)totalMemoryToAllocate,
            Lib.MEM_RESERVE,
            Lib.PAGE_EXECUTE_READWRITE);
        if (address == IntPtr.Zero)
            throw new InvalidOperationException($"Failed to allocate memory for sections. Error: {Marshal.GetLastWin32Error()}");

        int pagesAllocated = 0;
        for (int i = 0; i < _sectionHeaders.Count; i++)
        {
            var sectionHeader = _sectionHeaders[i];
            if (sectionHeader.SizeOfRawData == 0) continue;
            int sectionOffset = (int)sectionHeader.PointerToRawData;
            int sectionPages = (int)((sectionHeader.SizeOfRawData + Environment.SystemPageSize - 1) / Environment.SystemPageSize);
            int sectionMemorySize = sectionPages * Environment.SystemPageSize;
            var sectionAddress = Lib.VirtualAlloc(IntPtr.Add(address, pagesAllocated * Environment.SystemPageSize),
                                                  (uint)sectionMemorySize,
                                                  Lib.MEM_COMMIT,
                                                  Lib.PAGE_EXECUTE_READWRITE);
            _sectionAddresses[i] = sectionAddress;
            pagesAllocated += sectionPages;
            if (Lib.GetLastWin32Error() != SystemErrorCodes.ERROR_SUCCESS)
                throw new InvalidOperationException($"Failed to allocate memory for section '{System.Text.Encoding.ASCII.GetString(sectionHeader.Name)}'. Error: {Lib.GetLastWin32Error()}");
            if (RuntimeConfig.IsDebugEnabled)
                Console.WriteLine($"Section '{System.Text.Encoding.ASCII.GetString(sectionHeader.Name)}' allocated at: 0x{sectionAddress:X}, Size: {sectionMemorySize}");
            Marshal.Copy(_bofBytes, sectionOffset, sectionAddress, (int)sectionHeader.SizeOfRawData);
        }
        return (address, (uint)(pagesAllocated * Environment.SystemPageSize));
    }

    private void SetPermissionsForSections()
    {
        for (var i = 0; i < _sectionHeaders.Count; i++)
        {
            var section = _sectionHeaders[i];
            var sectionAddress = _sectionAddresses[i];
            var sectionName = System.Text.Encoding.ASCII.GetString(section.Name).TrimEnd('\0');
            int sectionPages = (int)((section.SizeOfRawData + Environment.SystemPageSize - 1) / Environment.SystemPageSize);
            int sectionMemorySize = sectionPages * Environment.SystemPageSize;
            var (x, r, w) = (section.Characteristics.HasFlag(SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE),
                             section.Characteristics.HasFlag(SectionCharacteristics.IMAGE_SCN_MEM_READ),
                             section.Characteristics.HasFlag(SectionCharacteristics.IMAGE_SCN_MEM_WRITE));
            uint pagePermissions = x && r && w ? Lib.PAGE_EXECUTE_READWRITE :
                                  x && r && !w ? Lib.PAGE_EXECUTE_READ :
                                  x && !r && !w ? Lib.PAGE_EXECUTE :
                                  !x && r && w ? Lib.PAGE_READWRITE :
                                  !x && r && !w ? Lib.PAGE_READONLY :
                                  !x && !r && !w ? Lib.PAGE_NOACCESS : 0;

            if (pagePermissions == 0)
                throw new InvalidOperationException($"Invalid page permissions for section: {section.Name}");
            if (RuntimeConfig.IsDebugEnabled)
                Console.WriteLine($"Setting permissions for section '{sectionName}' at address 0x{sectionAddress:X}, Size: {sectionMemorySize}, Permissions: {pagePermissions}");
            Lib.VirtualProtect(sectionAddress, (UIntPtr)sectionMemorySize, pagePermissions, out uint _);
        }
    }
    #endregion

    #region Relocation & Entry Point
    private void ResolveAllRelocations()
    {
        for (var i = 0; i < _sectionHeaders.Count; i++)
        {
            var sectionHeader = _sectionHeaders[i];
            var sectionAddress = _sectionAddresses[i];
            ResolveRelocations(sectionHeader, sectionAddress);
        }
    }

    private void ResolveRelocations(ImageSectionHeader sectionHeader, IntPtr sectionAddress)
    {
        if (sectionHeader.NumberOfRelocations == 0) return;
        int relocationOffset = (int)sectionHeader.PointerToRelocations;
        for (int i = 0; i < sectionHeader.NumberOfRelocations; i++)
        {
            var relocation = Deserialize<ImageRelocation>(
                _bofBytes.AsSpan(relocationOffset + (i * Marshal.SizeOf<ImageRelocation>()), Marshal.SizeOf<ImageRelocation>()).ToArray());
            if (RuntimeConfig.IsDebugEnabled)
                Console.WriteLine($"Relocation {i}: Virtual Address: 0x{relocation.VirtualAddress:X}, Symbol Index: {relocation.SymbolTableIndex:X}, Type: {relocation.Type}");
            if (relocation.SymbolTableIndex > _symbols.Count)
                throw new Exception($"Relocation symbol index out of range: {relocation.SymbolTableIndex} - total symbols: {_symbols.Count}");
            var symbol = _symbols[(int)relocation.SymbolTableIndex];
            var symbolName = LookupSymbolName(symbol);
            if (symbol.SectionNumber == ImageSectionNumber.IMAGE_SYM_UNDEFINED)
            {
                RelocateExternalSymbol(sectionAddress, symbol, relocation);
            }
            else
            {
                RelocateInternalSymbol(sectionAddress, symbol, relocation);
            }
        }
    }

    private void RelocateExternalSymbol(IntPtr sectionAddress, ImageSymbol symbol, ImageRelocation relocation)
    {
        if (symbol.SectionNumber != ImageSectionNumber.IMAGE_SYM_UNDEFINED)
            throw new InvalidOperationException($"Symbol '{LookupSymbolName(symbol)}' is not an external reference.");

        var relocationAddress = sectionAddress + (int)relocation.VirtualAddress;

        var baseSymbolName = LookupSymbolName(symbol).StartsWith(_importPrefix) ? LookupSymbolName(symbol).Substring(_importPrefix.Length) : LookupSymbolName(symbol);
        IntPtr functionAddress = IntPtr.Zero;
        if (baseSymbolName.Contains('$'))
        {
            var parts = baseSymbolName.Split('$');
            var libraryName = parts[0];
            var functionName = parts[1];
            functionAddress = _importAddressTable.ResolveLibrary(libraryName, functionName);
        }

        switch (relocation.Type)
        {
            case ImageRelocationType.IMAGE_REL_AMD64_REL32:
                Marshal.WriteInt32(relocationAddress,
                                       (int)((functionAddress.ToInt64() - 4) - (relocationAddress.ToInt64())));
                break;
            default:
                throw new NotSupportedException($"Unsupported relocation type: {relocation.Type}");
        }
        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine($"Relocated external symbol '{baseSymbolName}' to address: 0x{functionAddress:X} at relocation address: 0x{relocationAddress:X}");
    }

    private void RelocateInternalSymbol(IntPtr sectionAddress, ImageSymbol symbol, ImageRelocation relocation)
    {
        var relocationAddress = sectionAddress + (int)relocation.VirtualAddress;
        int symbolOffset;
        if (symbol.StorageClass == ImageSymbolStorageClass.IMAGE_SYM_CLASS_STATIC && symbol.Value != 0)
        {
            symbolOffset = (int)symbol.Value;
        }
        else if (symbol.StorageClass == ImageSymbolStorageClass.IMAGE_SYM_CLASS_EXTERNAL && symbol.SectionNumber != 0)
        {
            symbolOffset = (int)symbol.Value;
        }
        else
        {
            symbolOffset = Marshal.ReadInt32(relocationAddress);
        }

        Int64 addr;
        switch (relocation.Type)
        {
            case ImageRelocationType.IMAGE_REL_AMD64_REL32:

                addr = symbolOffset + _sectionAddresses[(int)symbol.SectionNumber - 1].ToInt64();
                Marshal.WriteInt32(relocationAddress,
                                   (int)((addr - 4) - relocationAddress.ToInt64()));

                break;
            case ImageRelocationType.IMAGE_REL_AMD64_ADDR32NB:
                addr = symbolOffset + _sectionAddresses[(int)symbol.SectionNumber - 1].ToInt64();
                Marshal.WriteInt32(relocationAddress,
                                   (int)(addr - relocationAddress.ToInt64()));
                break;
            default:
                throw new NotSupportedException($"Unsupported relocation type: {relocation.Type}");
        }

        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine($"Relocated internal symbol '{LookupSymbolName(symbol)}' to address: 0x{addr:X} at relocation address: 0x{relocationAddress:X}");
    }

    private void SetBOFVariables()
    {
        foreach (var symbol in _symbols)
        {
            var symbolName = LookupSymbolName(symbol);
            if (symbolName == "debug")
            {
                var symbol_addr = new IntPtr(_sectionAddresses[(int)symbol.SectionNumber - 1].ToInt64() + symbol.Value);

                if (RuntimeConfig.IsDebugEnabled)
                {
                    Marshal.WriteInt32(symbol_addr, 1);
                }
                else
                {
                    Marshal.WriteInt32(symbol_addr, 0);
                }

                if (RuntimeConfig.IsDebugEnabled)
                    Console.WriteLine($"Set debug variable '{symbolName}' to {(RuntimeConfig.IsDebugEnabled ? 1 : 0)} at address: {symbol_addr:X}");
            }
        }
    }

    private IntPtr ResolveEntryPoint(string entryPointName)
    {
        if (string.IsNullOrEmpty(entryPointName))
            throw new ArgumentException("Entry point name cannot be null or empty.");
        var symbol = _symbols.FirstOrDefault(s => LookupSymbolName(s) == entryPointName);
        if (symbol.SectionNumber == ImageSectionNumber.IMAGE_SYM_UNDEFINED)
            throw new InvalidOperationException($"Entry point '{entryPointName}' is an external reference and cannot be resolved directly.");
        var entryAddress = (IntPtr)(_sectionAddresses[(int)symbol.SectionNumber - 1].ToInt64() + (int)symbol.Value);
        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine($"Resolved entry point '{LookupSymbolName(symbol)}' at {entryAddress:X}");
        return entryAddress;
    }

    private void ExecuteEntryPoint(IntPtr entryAddress)
    {
        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine($"Executing entry point at address: 0x{entryAddress:X}");
        GoDelegate goFunc = Marshal.GetDelegateForFunctionPointer<GoDelegate>(entryAddress);
        try
        {
            goFunc();
            //var thread = Lib.CreateThread(IntPtr.Zero,
            //                              0,
            //                              entryAddress,
            //                              IntPtr.Zero,
            //                              0,
            //                              IntPtr.Zero);
            //var response = Lib.WaitForSingleObject(thread, 200);
        }
        catch (Exception ex)
        {
            var error = Lib.GetLastWin32Error();
            Console.WriteLine($"Error executing entry point: {ex.Message} - {error}");
            throw;
        }
    }
    #endregion

    #region Symbol & Utility
    private string LookupSymbolName(ImageSymbol symbol)
    {
        if (symbol.Name[0] == 0)
        {
            int offset = BitConverter.ToInt32(symbol.Name, 4) + (int)_stringTableOffset;
            if (offset < _stringTableOffset || offset >= _bofBytes.Length)
                throw new InvalidOperationException("Invalid symbol name offset.");
            var name = _bofBytes.Skip(offset).TakeWhile(b => b != '\0').ToArray();
            return System.Text.Encoding.ASCII.GetString(name);
        }
        else
        {
            return System.Text.Encoding.ASCII.GetString(symbol.Name).TrimEnd('\0');
        }
    }

    private static T Deserialize<T>(byte[] data) where T : struct
    {
        GCHandle handle = GCHandle.Alloc(data, GCHandleType.Pinned);
        try
        {
            return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        }
        finally
        {
            handle.Free();
        }
    }

    private void Clear()
    {
        _importAddressTable.Clear();
        for (var i = 0; i < _sectionHeaders.Count; i++)
        {
            var sectionHeader = _sectionHeaders[i];
            var sectionAddress = _sectionAddresses[i];
            Lib.VirtualProtect(sectionAddress, sectionHeader.SizeOfRawData, Lib.PAGE_READWRITE, out _);
        }
        Lib.ZeroMemory(_baseAddress, (int)_totalMemoryAllocated);
        Lib.VirtualFree(_baseAddress, 0, Lib.MEM_RELEASE);
    }
    #endregion
}
