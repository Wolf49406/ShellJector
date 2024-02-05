# ShellJector (v2.0)
Manual map shellcode (aka byte array) injector wich can download DLL from the internet by URL

![build status](https://github.com/Wolf49406/ShellJector/actions/workflows/msbuild.yml/badge.svg)


### Build:
- Open `ShellJector.sln -> main.cpp`;
- Set `ProcName` and `DllURL`;
- Build;

### Usage:
- Go to \ShellJector\Build\\`Configuration` (Release\Debug);
  - OR just download the [Latest Release](https://github.com/Wolf49406/ShellJector/releases/latest);
  - Set launch arguments (down below);
- Open Target Process;
- Open `ShellJector.exe`;

### Arguments:
You can set `ProcName` and `DllURL` with `-proc` and `-url` arguments  
(ex: `ShellJector.exe -proc Explorer.exe -url "https://example.com/library.dll"`)
