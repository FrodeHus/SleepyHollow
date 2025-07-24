using System.Runtime.InteropServices;

namespace SleepyHollow.Bof.Types;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct ImageSectionHeader
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Name; // 0x00
    public uint VirtualSize; // 0x08
    public uint VirtualAddress; // 0x0C
    public uint SizeOfRawData; // 0x10
    public uint PointerToRawData; // 0x14
    public uint PointerToRelocations; // 0x18
    public uint PointerToLinenumbers; // 0x1C
    public ushort NumberOfRelocations; // 0x20
    public ushort NumberOfLinenumbers; // 0x22
    public uint Characteristics; // 0x24
}
