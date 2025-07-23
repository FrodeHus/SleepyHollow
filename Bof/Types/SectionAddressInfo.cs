namespace SleepyHollow.Bof.Types;

internal record SectionAddressInfo(IntPtr Address, uint Characteristics, int Size, string SectionName);