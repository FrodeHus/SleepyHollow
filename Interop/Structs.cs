using System.Runtime.InteropServices;

namespace SleepyHollow;

[StructLayout(LayoutKind.Sequential)]
internal class SecurityAttributes
{
    public int Length;
    public IntPtr lpSecurityDescriptor = IntPtr.Zero;
    public bool bInheritHandle;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
internal struct ProcessInformation
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
internal struct StartupInfo
{
    public int cb;
    public IntPtr lpReserved;
    public IntPtr lpDesktop;
    public IntPtr lpTitle;
    public int dwX;
    public int dwY;
    public int dwXSize;
    public int dwYSize;
    public int dwXCountChars;
    public int dwYCountChars;
    public int dwFillAttribute;
    public int dwFlags;
    public short wShowWindow;
    public short cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
internal struct ProcessBasicInformation
{
    public IntPtr Reserved1;
    public IntPtr PebAddress;
    public IntPtr Reserved2;
    public IntPtr Reserved3;
    public IntPtr UniquePid;
    public IntPtr MoreReserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct ProcessMemoryCounters
{
    public uint cb;
    public uint PageFaultCount;
    public UIntPtr PeakWorkingSetSize;
    public UIntPtr WorkingSetSize;
    public UIntPtr QuotaPeakPagedPoolUsage;
    public UIntPtr QuotaPagedPoolUsage;
    public UIntPtr QuotaPeakNonPagedPoolUsage;
    public UIntPtr QuotaNonPagedPoolUsage;
    public UIntPtr PagefileUsage;
    public UIntPtr PeakPagefileUsage;
}

[StructLayout(LayoutKind.Sequential)]
internal struct QueryServiceConfigStruct
{
    public int serviceType;
    public int startType;
    public int errorControl;
    public IntPtr binaryPathName;
    public IntPtr loadOrderGroup;
    public int tagID;
    public IntPtr dependencies;
    public IntPtr startName;
    public IntPtr displayName;
}

public struct TOKEN_PRIVILEGES
{
    public uint PrivilegeCount;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 35)]
    public LUID_AND_ATTRIBUTES[] Privileges;
}

[StructLayout(LayoutKind.Sequential)]
public struct LUID_AND_ATTRIBUTES
{
    public LUID Luid;
    public uint Attributes;
}

[StructLayout(LayoutKind.Sequential)]
public struct LUID
{
    public uint LowPart;
    public int HighPart;
}

[StructLayout(LayoutKind.Sequential)]
struct SID_AND_ATTRIBUTES
{
    public IntPtr Sid;
    public uint Attributes;
}

[StructLayout(LayoutKind.Sequential)]
struct TOKEN_USER
{
    public SID_AND_ATTRIBUTES User;
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO
{
    public Int32 cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public Int32 dwX;
    public Int32 dwY;
    public Int32 dwXSize;
    public Int32 dwYSize;
    public Int32 dwXCountChars;
    public Int32 dwYCountChars;
    public Int32 dwFillAttribute;
    public Int32 dwFlags;
    public Int16 wShowWindow;
    public Int16 cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}
