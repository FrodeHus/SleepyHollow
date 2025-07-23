namespace SleepyHollow.Bof;

public static class BofExtensions
{
    public static bool HasFlag(this uint value, uint flag)
    {
        return (value & flag) == flag;
    }
}
