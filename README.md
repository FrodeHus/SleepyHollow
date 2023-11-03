# Sleepy Hollow

## Build

Build native AOT executable with `dotnet publish -c Release --self-contained`

## Usage

Use `SleepyHollow.exe --help` to see the usage information.

```text
Description:
  SleepyHollow

Usage:
  SleepyHollow [command] [options]

Options:
  --skip-evasion  Do not perform sandbox evasion checks
  --debug         Enable debug logging
  --version       Show version information
  -?, -h, --help  Show help and usage information

Commands:
  sc                           Injects and runs shellcode
  dll <processName> <dllName>  Injects and runs DLL
```