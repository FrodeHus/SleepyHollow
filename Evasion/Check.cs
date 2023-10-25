using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SleepyHollow;

internal static class EvasionCheck
{
    internal static bool Detected => IsDebuggerPresent() || IsFirstEventLogLessThanDayOld() || IsTimeFastForwarded() || CheckProcessMemory();

    internal static bool IsTimeFastForwarded()
    {
        var startTime = DateTime.Now;
        Task.Delay(2000).Wait();

        double elapsed = (DateTime.Now - startTime).TotalSeconds;
        if (elapsed < 1.5)
        {
            return true;
        }
        return false;
    }

    internal static bool IsFirstEventLogLessThanDayOld()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            EventLog log = new("System");

            if (log.Entries.Count > 0)
            {
                var firstEvent = log.Entries[0];
                var age = DateTime.Now - firstEvent.TimeGenerated;

                var freshEventLog = age.TotalDays < 1;
                return freshEventLog;
            }
        }
        return false;
    }

    internal static bool IsDebuggerPresent()
    {
        var isDebuggerPresent = false;
        Lib.CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
        return isDebuggerPresent;
    }

    internal static bool CheckProcessMemory()
    {

        var size = (uint)Marshal.SizeOf<ProcessMemoryCounters>();
        if (!Lib.GetProcessMemoryInfo(Lib.GetCurrentProcess(), out ProcessMemoryCounters pmc, size))
        {
            Console.WriteLine("Error getting process memory info: " + Lib.GetLastWin32Error());
            return true;
        }
        if (pmc.WorkingSetSize <= 10000000)
        {
            return false;
        }
        else
        {
            Console.WriteLine($"- Process memory is greater than 10MB: {pmc.WorkingSetSize}");
            return true;
        }
    }
}