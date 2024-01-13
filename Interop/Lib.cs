using System.Runtime.InteropServices;
using System.Text;

namespace SleepyHollow;

[Flags]
public enum OpenProcessFlags : uint
{
    PROCESS_ALL_ACCESS = 0x001F0FFF
}

[Flags]
public enum CreationFlags
{
    DefaultErrorMode = 0x04000000,
    NewConsole = 0x00000010,
    NewProcessGroup = 0x00000200,
    SeparateWOWVDM = 0x00000800,
    Suspended = 0x00000004,
    UnicodeEnvironment = 0x00000400,
    ExtendedStartupInfoPresent = 0x00080000
}

[Flags]
public enum LogonFlags
{
    WithProfile = 1,
    NetCredentialsOnly
}

[Flags]
public enum CreateProcessFlags : uint
{
    DEBUG_PROCESS = 0x00000001,
    DEBUG_ONLY_THIS_PROCESS = 0x00000002,
    CREATE_SUSPENDED = 0x00000004,
    DETACHED_PROCESS = 0x00000008,
    CREATE_NEW_CONSOLE = 0x00000010,
    NORMAL_PRIORITY_CLASS = 0x00000020,
    IDLE_PRIORITY_CLASS = 0x00000040,
    HIGH_PRIORITY_CLASS = 0x00000080,
    REALTIME_PRIORITY_CLASS = 0x00000100,
    CREATE_NEW_PROCESS_GROUP = 0x00000200,
    CREATE_UNICODE_ENVIRONMENT = 0x00000400,
    CREATE_SEPARATE_WOW_VDM = 0x00000800,
    CREATE_SHARED_WOW_VDM = 0x00001000,
    CREATE_FORCEDOS = 0x00002000,
    BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
    ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
    INHERIT_PARENT_AFFINITY = 0x00010000,
    INHERIT_CALLER_PRIORITY = 0x00020000,
    CREATE_PROTECTED_PROCESS = 0x00040000,
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
    PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
    PROCESS_MODE_BACKGROUND_END = 0x00200000,
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
    CREATE_DEFAULT_ERROR_MODE = 0x04000000,
    CREATE_NO_WINDOW = 0x08000000,
    PROFILE_USER = 0x10000000,
    PROFILE_KERNEL = 0x20000000,
    PROFILE_SERVER = 0x40000000,
    CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
}

[Flags]
internal enum ACCESS_MASK : uint
{
    STANDARD_RIGHTS_REQUIRED = 0x000F0000,
    STANDARD_RIGHTS_READ = 0x00020000,
    STANDARD_RIGHTS_WRITE = 0x00020000,
    STANDARD_RIGHTS_EXECUTE = 0x00020000,
}

[Flags]
internal enum SCM_ACCESS : uint
{
    SC_MANAGER_CONNECT = 0x00001,
    SC_MANAGER_CREATE_SERVICE = 0x00002,
    SC_MANAGER_ENUMERATE_SERVICE = 0x00004,
    SC_MANAGER_LOCK = 0x00008,
    SC_MANAGER_QUERY_LOCK_STATUS = 0x00010,
    SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00020,
    SC_MANAGER_ALL_ACCESS =
        ACCESS_MASK.STANDARD_RIGHTS_REQUIRED
        | SC_MANAGER_CONNECT
        | SC_MANAGER_CREATE_SERVICE
        | SC_MANAGER_ENUMERATE_SERVICE
        | SC_MANAGER_LOCK
        | SC_MANAGER_QUERY_LOCK_STATUS
        | SC_MANAGER_MODIFY_BOOT_CONFIG,

    GENERIC_READ =
        ACCESS_MASK.STANDARD_RIGHTS_READ
        | SC_MANAGER_ENUMERATE_SERVICE
        | SC_MANAGER_QUERY_LOCK_STATUS,

    GENERIC_WRITE =
        ACCESS_MASK.STANDARD_RIGHTS_WRITE
        | SC_MANAGER_CREATE_SERVICE
        | SC_MANAGER_MODIFY_BOOT_CONFIG,

    GENERIC_EXECUTE = ACCESS_MASK.STANDARD_RIGHTS_EXECUTE | SC_MANAGER_CONNECT | SC_MANAGER_LOCK,

    GENERIC_ALL = SC_MANAGER_ALL_ACCESS,
}

//This enum was huge, I cut it down to save space
public enum TOKEN_INFORMATION_CLASS
{
    /// <summary>
    /// The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
    /// </summary>
    TokenUser = 1,
    TokenPrivileges = 3
}

[Flags]
internal enum SERVICE_ACCESS : uint
{
    STANDARD_RIGHTS_REQUIRED = 0xF0000,
    SERVICE_QUERY_CONFIG = 0x00001,
    SERVICE_CHANGE_CONFIG = 0x00002,
    SERVICE_QUERY_STATUS = 0x00004,
    SERVICE_ENUMERATE_DEPENDENTS = 0x00008,
    SERVICE_START = 0x00010,
    SERVICE_STOP = 0x00020,
    SERVICE_PAUSE_CONTINUE = 0x00040,
    SERVICE_INTERROGATE = 0x00080,
    SERVICE_USER_DEFINED_CONTROL = 0x00100,
    SERVICE_ALL_ACCESS =
        (
            STANDARD_RIGHTS_REQUIRED
            | SERVICE_QUERY_CONFIG
            | SERVICE_CHANGE_CONFIG
            | SERVICE_QUERY_STATUS
            | SERVICE_ENUMERATE_DEPENDENTS
            | SERVICE_START
            | SERVICE_STOP
            | SERVICE_PAUSE_CONTINUE
            | SERVICE_INTERROGATE
            | SERVICE_USER_DEFINED_CONTROL
        )
}

internal static partial class Lib
{
    internal static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
    internal static UInt32 MEM_COMMIT = 0x1000;
    internal static UInt32 MEM_COMMIT_AND_RESERVE = 0x3000;

    [LibraryImport(
        "kernel32.dll",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16
    )]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CreateProcessW(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
        CreateProcessFlags dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref StartupInfo lpStartupInfo,
        out ProcessInformation lpProcessInformation
    );

    [LibraryImport("ntdll.dll")]
    internal static partial int ZwQueryInformationProcess(
        IntPtr hProcess,
        int procInformationClass,
        ref ProcessBasicInformation procInformation,
        uint ProcInfoLen,
        ref uint retlen
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesWritten
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial uint ResumeThread(IntPtr hThread);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CheckRemoteDebuggerPresent(
        IntPtr hProcess,
        [MarshalAs(UnmanagedType.Bool)] ref bool isDebuggerPresent
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr OpenProcess(
        OpenProcessFlags dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        int dwProcessId
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr VirtualAllocExNuma(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect,
        uint nndPreferred
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId
    );

    [LibraryImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetProcessMemoryInfo(
        IntPtr hProcess,
        out ProcessMemoryCounters counters,
        uint size
    );

    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr GetCurrentProcess();

    [LibraryImport("kernel32.dll")]
    internal static partial uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [LibraryImport("kernel32", SetLastError = true)]
    internal static partial IntPtr GetProcAddress(
        IntPtr hModule,
        [MarshalAs(UnmanagedType.LPStr)] string procName
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    internal static extern IntPtr GetModuleHandle(string lpModuleName);

    [LibraryImport(
        "advapi32.dll",
        EntryPoint = "OpenSCManagerW",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16
    )]
    internal static partial IntPtr OpenSCManager(
        string lpMachineName,
        string lpDatabaseName,
        uint dwDesiredAccess
    );

    [LibraryImport("advapi32.dll", SetLastError = true, EntryPoint = "OpenServiceA")]
    internal static partial IntPtr OpenService(
        IntPtr hSCManager,
        [MarshalAs(UnmanagedType.LPStr)] string lpServiceName,
        uint dwDesiredAccess
    );

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ChangeServiceConfigA(
        IntPtr hService,
        uint dwServiceType,
        int dwStartType,
        int dwErrorControl,
        string lpBinaryPathName,
        string lpLoadOrderGroup,
        string lpdwTagId,
        string lpDependencies,
        string lpServiceStartName,
        string lpPassword,
        string lpDisplayName
    );

    [DllImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool StartService(
        IntPtr hService,
        int dwNumServiceArgs,
        string[] lpServiceArgVectors
    );

    [LibraryImport(
        "advapi32.dll",
        SetLastError = true,
        EntryPoint = "QueryServiceConfigW",
        StringMarshalling = StringMarshalling.Utf16
    )]
    internal static partial int QueryServiceConfig(
        IntPtr hService,
        IntPtr lpServiceConfig,
        int cbBufSize,
        ref int bytesNeeded
    );

    internal static SystemErrorCodes GetLastWin32Error()
    {
        return (SystemErrorCodes)Marshal.GetLastWin32Error();
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation,
        int TokenInformationLength,
        ref int ReturnLength
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LookupPrivilegeName(
        string lpSystemName,
        IntPtr lpLuid,
        StringBuilder lpName,
        ref int cchName
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    [DllImport("kernel32.dll")]
    public static extern uint GetSystemDirectory([Out] StringBuilder lpBuffer, uint uSize);

    [DllImport("userenv.dll", SetLastError = true)]
    public static extern bool CreateEnvironmentBlock(
        out IntPtr lpEnvironment,
        IntPtr hToken,
        bool bInherit
    );

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        UInt32 dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        UInt32 dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateNamedPipe(
        string lpName,
        uint dwOpenMode,
        uint dwPipeMode,
        uint nMaxInstances,
        uint nOutBufferSize,
        uint nInBufferSize,
        uint nDefaultTimeOut,
        IntPtr lpSecurityAttributes
    );

    [DllImport("kernel32.dll")]
    public static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

    [DllImport("advapi32.dll")]
    public static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentThread();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenThreadToken(
        IntPtr ThreadHandle,
        uint DesiredAccess,
        bool OpenAsSelf,
        out IntPtr TokenHandle
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool ConvertSidToStringSid(IntPtr pSid, out IntPtr ptrSid);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        uint ImpersonationLevel,
        uint TokenType,
        out IntPtr phNewToken
    );
}

internal enum SystemErrorCodes : uint
{
    ERROR_SUCCESS = 0x0,
    ERROR_INVALID_FUNCTION = 0x1,
    ERROR_FILE_NOT_FOUND = 0x2,
    ERROR_PATH_NOT_FOUND = 0x3,
    ERROR_ACCESS_DENIED = 0x5,
    ERROR_INVALID_HANDLE = 0x6,
    ERROR_NOT_ENOUGH_MEMORY = 0x8,
    ERROR_INVALID_DATA = 0xD,
    ERROR_INVALID_DRIVE = 0xF,
    ERROR_NO_MORE_FILES = 0x12,
    ERROR_NOT_READY = 0x15,
    ERROR_BAD_LENGTH = 0x18,
    ERROR_SHARING_VIOLATION = 0x20,
    ERROR_NOT_SUPPORTED = 0x32,
    ERROR_FILE_EXISTS = 0x50,
    ERROR_INVALID_PARAMETER = 0x57,
    ERROR_CALL_NOT_IMPLEMENTED = 0x78,
    ERROR_INSUFFICIENT_BUFFER = 0x7A,
    ERROR_INVALID_NAME = 0x7B,
    ERROR_BAD_PATHNAME = 0xA1,
    ERROR_ALREADY_EXISTS = 0xB7,
    ERROR_ENVVAR_NOT_FOUND = 0xCB,
    ERROR_FILENAME_EXCED_RANGE = 0xCE,
    ERROR_NO_DATA = 0xE8,
    ERROR_PIPE_NOT_CONNECTED = 0xE9,
    ERROR_MORE_DATA = 0xEA,
    ERROR_NO_MORE_ITEMS = 0x103,
    ERROR_VIRUS_INFECTED = 0xE1,
    ERROR_SERVICE_REQUEST_TIMEOUT = 0x41D,
    ERROR_SERVICE_ALREADY_RUNNING = 0x420,
}
