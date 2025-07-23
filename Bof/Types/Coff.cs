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
    private readonly List<SectionAddressInfo> _sectionAddressInfos = [];
    private readonly long _stringTableOffset;
    private readonly byte[] _bofBytes;
    private readonly string _importPrefix;
    private readonly IntPtr _baseAddress;
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
        _fileHeader = Deserialize<ImageFileHeader>(bofBytes.AsSpan(0, Marshal.SizeOf<ImageFileHeader>()).ToArray());
        _importPrefix = _fileHeader.Machine == ImageFileMachine.IMAGE_FILE_MACHINE_AMD64 ? "__imp_" : "__imp__";
        _stringTableOffset = _fileHeader.PointerToSymbolTable + (_fileHeader.NumberOfSymbols * Marshal.SizeOf<ImageSymbol>());

        ReadSectionHeaders(bofBytes);
        ReadSymbols(bofBytes);
        ValidateHeaderCounts();

        _baseAddress = WriteSectionsToMemory();
        ResolveAllRelocations();
        var entryPoint = ResolveEntryPoint("go");
        SetPermissionsForSections();
        ExecuteEntryPoint(entryPoint);
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
    private nint WriteSectionsToMemory()
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
            pagesAllocated += sectionPages;
            if (Lib.GetLastWin32Error() != SystemErrorCodes.ERROR_SUCCESS)
                throw new InvalidOperationException($"Failed to allocate memory for section '{System.Text.Encoding.ASCII.GetString(sectionHeader.Name)}'. Error: {Lib.GetLastWin32Error()}");
            if (RuntimeConfig.IsDebugEnabled)
                Console.WriteLine($"Section '{System.Text.Encoding.ASCII.GetString(sectionHeader.Name)}' allocated at: 0x{sectionAddress:X}, Size: {sectionMemorySize}");
            Marshal.Copy(_bofBytes, sectionOffset, sectionAddress, (int)sectionHeader.SizeOfRawData);
            var updatedSectionHeader = sectionHeader;
            updatedSectionHeader.PointerToRawData = (uint)(sectionAddress.ToInt64() - address.ToInt64());
            _sectionHeaders[_sectionHeaders.IndexOf(sectionHeader)] = updatedSectionHeader;
            _sectionAddressInfos.Add(new SectionAddressInfo(sectionAddress, sectionHeader.Characteristics, sectionMemorySize, System.Text.Encoding.ASCII.GetString(sectionHeader.Name)));
        }
        return address;
    }

    private void SetPermissionsForSections()
    {
        foreach (var section in _sectionAddressInfos)
        {
            var (x, r, w) = (section.Characteristics.HasFlag((uint)SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE),
                             section.Characteristics.HasFlag((uint)SectionCharacteristics.IMAGE_SCN_MEM_READ),
                             section.Characteristics.HasFlag((uint)SectionCharacteristics.IMAGE_SCN_MEM_WRITE));
            uint pagePermissions = x && r && w ? Lib.PAGE_EXECUTE_READWRITE :
                                  x && r && !w ? Lib.PAGE_EXECUTE_READ :
                                  x && !r && !w ? Lib.PAGE_EXECUTE :
                                  !x && r && w ? Lib.PAGE_READWRITE :
                                  !x && r && !w ? Lib.PAGE_READONLY :
                                  !x && !r && !w ? Lib.PAGE_NOACCESS : 0;
            if (pagePermissions == 0)
                throw new InvalidOperationException($"Invalid page permissions for section: {section.SectionName}");
            if (RuntimeConfig.IsDebugEnabled)
                Console.WriteLine($"Setting permissions for section '{section.SectionName}' at address 0x{section.Address:X}, Size: {section.Size}, Permissions: {pagePermissions}");
            Lib.VirtualProtect(section.Address, (UIntPtr)section.Size, pagePermissions, out uint _);
        }
    }
    #endregion

    #region Relocation & Entry Point
    private void ResolveAllRelocations()
    {
        foreach (var sectionHeader in _sectionHeaders)
        {
            if (RuntimeConfig.IsDebugEnabled)
                Console.WriteLine($"Resolving {sectionHeader.NumberOfRelocations} relocations for section: {System.Text.Encoding.ASCII.GetString(sectionHeader.Name)}");
            ResolveRelocations(sectionHeader);
        }
    }

    private void ResolveRelocations(ImageSectionHeader sectionHeader)
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
            if (RuntimeConfig.IsDebugEnabled)
                Console.WriteLine($"Relocation {i}: Symbol Name: {symbolName} - Type: {relocation.Type} - Storage Class: {symbol.StorageClass}");
            var functionAddress = IntPtr.Zero;
            if (symbol.SectionNumber == ImageSectionNumber.IMAGE_SYM_UNDEFINED)
            {
                if (RuntimeConfig.IsDebugEnabled)
                    Console.WriteLine($"Relocation {i}: External reference");
                var baseSymbolName = symbolName.StartsWith(_importPrefix) ? symbolName.Substring(_importPrefix.Length) : symbolName;
                if (baseSymbolName.Contains("$"))
                {
                    var parts = baseSymbolName.Split('$');
                    var dllName = parts[0];
                    var functionName = parts[1];
                    if (RuntimeConfig.IsDebugEnabled)
                        Console.WriteLine($"Relocation {i}: DLL: {dllName}, Function: {functionName}");
                    functionAddress = ResolveExternalReference(dllName, functionName);
                }
            }
            else
            {
                if (RuntimeConfig.IsDebugEnabled)
                    Console.WriteLine($"Relocation {i}: Internal reference");
            }
            IntPtr relocationAddress = _baseAddress + (int)sectionHeader.PointerToRawData + (int)relocation.VirtualAddress;
            var currentValue = Marshal.ReadInt32(relocationAddress);
            if (RuntimeConfig.IsDebugEnabled)
                Console.WriteLine($"Relocation {i}: Current Value at 0x{relocationAddress:X}: {currentValue:X}");
            switch (relocation.Type)
            {
                case ImageRelocationType.IMAGE_REL_AMD64_REL32:
                    Marshal.WriteInt32(
                        relocationAddress,
                        (int)((functionAddress.ToInt64() - 4) - (relocationAddress.ToInt64())));
                    break;
                case ImageRelocationType.IMAGE_REL_AMD64_ADDR32NB:
                    var addr = currentValue + (int)_sectionHeaders[(int)symbol.SectionNumber - 1].PointerToRawData;
                    Marshal.WriteInt32(
                        relocationAddress,
                        (int)(addr - relocationAddress.ToInt64()));
                    break;
                default:
                    throw new NotSupportedException($"Unsupported relocation type: {relocation.Type}");
            }
        }
    }

    private ImageSymbol ResolveEntryPoint(string entryPointName)
    {
        if (string.IsNullOrEmpty(entryPointName))
            throw new ArgumentException("Entry point name cannot be null or empty.");
        var symbol = _symbols.FirstOrDefault(s => LookupSymbolName(s) == entryPointName);
        if (symbol.SectionNumber == ImageSectionNumber.IMAGE_SYM_UNDEFINED)
            throw new InvalidOperationException($"Entry point '{entryPointName}' is an external reference and cannot be resolved directly.");
        return symbol;
    }

    private void ExecuteEntryPoint(ImageSymbol entryPoint)
    {
        var entryAddress = (IntPtr)(_baseAddress.ToInt64() + entryPoint.Value + _sectionHeaders[(int)entryPoint.SectionNumber - 1].PointerToRawData);
        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine($"Executing entry point: {LookupSymbolName(entryPoint)} at address: 0x{entryAddress:X}");
        GoDelegate goFunc = Marshal.GetDelegateForFunctionPointer<GoDelegate>((IntPtr)(_baseAddress.ToInt64() + entryPoint.Value));
        try
        {
            //goFunc();
            var thread = Lib.CreateThread(IntPtr.Zero,
                                          0,
                                          entryAddress,
                                          IntPtr.Zero,
                                          0,
                                          IntPtr.Zero);
            var response = Lib.WaitForSingleObject(thread, 200);
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
    private static IntPtr ResolveExternalReference(string dllName, string functionName)
    {
        var dllHandle = Lib.LoadLibrary(dllName);
        if (dllHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Failed to load DLL '{dllName}'. Error: {Marshal.GetLastWin32Error()}");
        var functionAddress = Lib.GetProcAddress(dllHandle, functionName);
        if (functionAddress == IntPtr.Zero)
            throw new InvalidOperationException($"Failed to get address of function '{functionName}' in DLL '{dllName}'. Error: {Marshal.GetLastWin32Error()}");
        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine($"Resolved function '{functionName}' in DLL '{dllName}' at address: 0x{functionAddress:X}");
        return functionAddress;
    }

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
    #endregion
}
