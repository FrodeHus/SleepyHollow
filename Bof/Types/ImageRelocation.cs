using System.Runtime.InteropServices;

namespace SleepyHollow.Bof.Types;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct ImageRelocation
{
    public uint VirtualAddress; // 0x00
    public uint SymbolTableIndex; // 0x04
    public ImageRelocationType Type; // 0x08
}
