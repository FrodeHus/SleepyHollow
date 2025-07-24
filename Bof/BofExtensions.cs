
using SleepyHollow.Bof.Types;

namespace SleepyHollow.Bof;

public static class BofExtensions
{
    public static bool HasFlag(this uint value, SectionCharacteristics flag)
    {
        return (value & (uint)flag) == (uint)flag;
    }
}
