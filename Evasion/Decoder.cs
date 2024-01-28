using System.Text;

namespace SleepyHollow;

internal static class Decoder
{
    internal static byte[] DecodeString(string encoded)
    {
        var hex = encoded.Replace("\n", "");
        return Enumerable
            .Range(0, hex.Length)
            .Where(x => x % 2 == 0)
            .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
            .ToArray();
    }

    internal static byte[] XorBytes(int key, byte[] buf)
    {
        for (int i = 0; i < buf.Length; i++)
        {
            buf[i] = (byte)((uint)buf[i] ^ key);
        }
        return buf;
    }
}
