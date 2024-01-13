using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;

namespace SleepyHollow;

#pragma warning disable CA1416 // Validate platform compatibility

internal static class UserHelper
{
    internal static string GetUserName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return WindowsIdentity.GetCurrent()?.Name;
        }
        throw new Exception("Unsupported OS");
    }

    internal static bool IsAdmin()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        throw new Exception("Unsupported OS");
    }

    internal static bool IsMemberOfAdministrators()
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (identity != null)
        {
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            List<Claim> list = new(principal.UserClaims);
            Claim c = list.Find(p => p.Value.Contains("S-1-5-32-544"));
            if (c != null)
                return true;
        }
        return false;
    }

    internal static Dictionary<string, bool> CheckPrivileges()
    {
        var privileges = new Dictionary<string, bool>();
        int TokenInfLength = 0;
        IntPtr ThisHandle = WindowsIdentity.GetCurrent().Token;
        Lib.GetTokenInformation(
            ThisHandle,
            TOKEN_INFORMATION_CLASS.TokenPrivileges,
            IntPtr.Zero,
            TokenInfLength,
            ref TokenInfLength
        );
        IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
        if (
            Lib.GetTokenInformation(
                WindowsIdentity.GetCurrent().Token,
                TOKEN_INFORMATION_CLASS.TokenPrivileges,
                TokenInformation,
                TokenInfLength,
                ref TokenInfLength
            )
        )
        {
            TOKEN_PRIVILEGES ThisPrivilegeSet = (TOKEN_PRIVILEGES)
                Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_PRIVILEGES));
            for (int index = 0; index < ThisPrivilegeSet.PrivilegeCount; index++)
            {
                LUID_AND_ATTRIBUTES laa = ThisPrivilegeSet.Privileges[index];
                StringBuilder privNameBuilder = new StringBuilder();
                int LuidNameLen = 0;
                IntPtr LuidPointer = Marshal.AllocHGlobal(Marshal.SizeOf(laa.Luid));
                Marshal.StructureToPtr(laa.Luid, LuidPointer, true);
                Lib.LookupPrivilegeName(null, LuidPointer, null, ref LuidNameLen);
                privNameBuilder.EnsureCapacity(LuidNameLen + 1);
                if (Lib.LookupPrivilegeName(null, LuidPointer, privNameBuilder, ref LuidNameLen))
                {
                    var attribute = laa.Attributes.ToString();
                    privileges.Add(privNameBuilder.ToString(), attribute == "3");
                }
                Marshal.FreeHGlobal(LuidPointer);
            }
        }
        return privileges;
    }
}
