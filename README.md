# ExecIT

## Description
DLL Shellcode self-inyector/runner based on HWSyscalls, ideally thought to be executed with rundll32. May grant fileless execution if victim endpoint has access to attacker-controlled SMB share.

## Usage
```powershell
rundll32.exe ExecIT.dll, HelperFunc, <path_to_file>
```
