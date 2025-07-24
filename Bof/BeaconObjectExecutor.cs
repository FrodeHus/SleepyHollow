using SleepyHollow.Bof.Types;
using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

namespace SleepyHollow.Bof;

internal class BeaconObjectExecutor(string file)
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void GoDelegate();
    public void Run()
    {
        var bofData = File.ReadAllBytes(file);
        if (bofData.Length == 0)
        {
            Console.WriteLine("Failed to download BOF data.");
            Environment.Exit(1);
        }
        using var coff = new Coff(bofData);
        var entryPoint = coff.ResolveEntryPoint("go");
        try
        {
            ExecuteEntryPoint(entryPoint);
        }catch(Exception ex)
        {
            Console.WriteLine($"Error executing BOF: {ex.Message}");
        }
    }

    private void ExecuteEntryPoint(IntPtr entryAddress)
    {
        if (RuntimeConfig.IsDebugEnabled)
            Console.WriteLine($"Executing entry point at address: 0x{entryAddress:X}");
        GoDelegate goFunc = Marshal.GetDelegateForFunctionPointer<GoDelegate>(entryAddress);
        try
        {
            if (RuntimeConfig.IsDebugEnabled)
                Console.WriteLine("==> [BOF Output]");
            goFunc();
        }
        catch (Exception ex)
        {
            var error = Lib.GetLastWin32Error();
            Console.WriteLine($"Error executing entry point: {ex.Message} - {error}");
            throw;
        }
    }
}
