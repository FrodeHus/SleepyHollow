using System.Runtime.InteropServices;

namespace SleepyHollow;

[Flags]
public enum OpenProcessFlags : uint
{
    PROCESS_ALL_ACCESS = 0x001F0FFF
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


internal static partial class Lib
{
    internal static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
    internal static UInt32 MEM_COMMIT = 0x1000;
    internal static UInt32 MEM_COMMIT_AND_RESERVE = 0x3000;

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles, CreateProcessFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref StartupInfo lpStartupInfo, out ProcessInformation lpProcessInformation);

    [LibraryImport("ntdll.dll")]
    internal static partial int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref ProcessBasicInformation procInformation, uint ProcInfoLen, ref uint retlen);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial uint ResumeThread(IntPtr hThread);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CheckRemoteDebuggerPresent(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] ref bool isDebuggerPresent);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr OpenProcess(OpenProcessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect, uint nndPreferred);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [LibraryImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetProcessMemoryInfo(IntPtr hProcess, out ProcessMemoryCounters counters, uint size);
    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr GetCurrentProcess();

    [LibraryImport("kernel32.dll")]
    internal static partial uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [LibraryImport("kernel32", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    internal static extern IntPtr GetModuleHandle(string lpModuleName);
    internal static SystemErrorCodes GetLastWin32Error()
    {
        return (SystemErrorCodes)Marshal.GetLastWin32Error();
    }
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
}