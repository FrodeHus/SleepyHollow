namespace SleepyHollow;

internal static class Decoder
{
    internal static byte[] DecodeString(string encoded)
    {
        var hex = encoded.Replace("\n", "");
        return Enumerable.Range(0, hex.Length)
            .Where(x => x % 2 == 0)
            .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
            .ToArray();
    }
}