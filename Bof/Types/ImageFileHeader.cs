using System.Runtime.InteropServices;

namespace SleepyHollow.Bof.Types;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct ImageFileHeader
{
    public ImageFileMachine Machine; // 0x00
    public UInt16 NumberOfSections; // 0x02
    public UInt32 TimeDateStamp; // 0x04
    public UInt32 PointerToSymbolTable; // 0x08
    public UInt32 NumberOfSymbols; // 0x0C
    public UInt16 SizeOfOptionalHeader; // 0x10
    public UInt16 Characteristics; // 0x12
}