using System.Reflection;

namespace SleepyHollow;

internal static class FileSystem
{
    internal static async Task<byte[]> ReadFile(string path)
    {        
        return await File.ReadAllBytesAsync(path);
    }

    internal static async Task WriteFile(string path, byte[] data)
    {
        await File.WriteAllBytesAsync(path, data);
    }

    internal static string FindWriteableDirectory()
    {
        var possiblePaths = new string[]{
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Directory.GetCurrentDirectory()
        };
        foreach (var path in possiblePaths)
        {
            if (Directory.Exists(path) && CanWriteToDirectory(path))
            {
                return path;
            }
        }
        return null;
    }

    private static bool CanWriteToDirectory(string path)
    {
        try
        {
            var testFile = Path.Combine(path, Guid.NewGuid().ToString());
            File.WriteAllText(testFile, "test");
            File.Delete(testFile);
            return true;
        }
        catch
        {
            return false;
        }
    }
}