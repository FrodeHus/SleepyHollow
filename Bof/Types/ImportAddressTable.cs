using System.Runtime.InteropServices;

namespace SleepyHollow.Bof.Types;

internal class ImportAddressTable
{
    private readonly Dictionary<string, IntPtr> _importAddresses = [];
    private readonly IntPtr _iatAddress;
    public ImportAddressTable()
    {
        _iatAddress = Lib.VirtualAlloc(IntPtr.Zero, (uint)(2 * Environment.SystemPageSize), Lib.MEM_COMMIT, Lib.PAGE_EXECUTE_READWRITE);
    }

    public IntPtr AddImportAddress(string importName, IntPtr address)
    {
        Marshal.WriteInt64(_iatAddress + (_importAddresses.Count * Environment.SystemPageSize), address.ToInt64());
        _importAddresses[importName] = _iatAddress + (_importAddresses.Count * 8);
        return _importAddresses[importName];
    }

    public IntPtr ResolveLibrary(string libraryName, string functionName)
    {
        if (!_importAddresses.TryGetValue($"{libraryName}${functionName}", out var address))
        {
            var handle = Lib.LoadLibrary(libraryName);
            address = Lib.GetProcAddress(handle, functionName);
            if (address == IntPtr.Zero)
            {
                throw new InvalidOperationException($"Function '{functionName}' not found in library '{libraryName}'.");
            }
            if (RuntimeConfig.IsDebugEnabled)
                Console.WriteLine($"Resolved function '{functionName}' in library '{libraryName}' at address: 0x{address:X}");
            AddImportAddress($"{libraryName}${functionName}", address);
        }
        return _importAddresses[$"{libraryName}${functionName}"];
    }

    public void Clear()
    {
        _importAddresses.Clear();
        Lib.ZeroMemory(_iatAddress, (2 * Environment.SystemPageSize));
        Lib.VirtualFree(_iatAddress, 0, Lib.MEM_RELEASE);
    }
}
