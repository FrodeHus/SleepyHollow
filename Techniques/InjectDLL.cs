using System.Diagnostics;
using System.Text;

namespace SleepyHollow;

internal static class InjectDLL
{
    internal static Task Run(string dllName, string processName = "explorer", bool debug = false)
    {
        var process = Process.GetProcessesByName(processName);
        if (process.Length == 0)
        {
            Console.WriteLine("Process not found");
            return Task.CompletedTask;
        }

        var pid = process[0].Id;
        if(debug) Console.WriteLine($"Process ID: {pid}");

        IntPtr hProcess = Lib.OpenProcess(OpenProcessFlags.PROCESS_ALL_ACCESS, false, pid);
        if(debug) Console.WriteLine($"Process handle: 0x{hProcess:X}");

        IntPtr lpAddress = Lib.VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, Lib.MEM_COMMIT_AND_RESERVE, Lib.PAGE_EXECUTE_READWRITE);
        if(debug) Console.WriteLine($"Allocated address: 0x{lpAddress:X}");
        var res = Lib.WriteProcessMemory(hProcess, lpAddress, Encoding.Default.GetBytes(dllName), dllName.Length, out nint outSize);
        if (debug) Console.WriteLine($"WriteProcessMemory result: {res} - Bytes written: {outSize}");
        IntPtr loadLib = Lib.GetProcAddress(Lib.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        if(debug) Console.WriteLine($"LoadLibraryA address: 0x{loadLib:X}");
        IntPtr hThread = Lib.CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, lpAddress, 0, IntPtr.Zero);
        if(debug) Console.WriteLine($"Thread creation successful - Thread handle: 0x{hThread:x8}");
        return Task.CompletedTask;
    }
}