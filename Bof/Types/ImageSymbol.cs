using System.Runtime.InteropServices;

namespace SleepyHollow.Bof.Types;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct ImageSymbol
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Name; // 0x00
    public UInt32 Value; // 0x08
    public ImageSectionNumber SectionNumber; // 0x0C
    public ImageSymbolType Type; // 0x0E
    public ImageSymbolStorageClass StorageClass; // 0x10
    public byte NumberOfAuxSymbols; // 0x11
}
