# ExecIT

## Description
DLL Shellcode self-inyector/runner based on HWSyscalls, ideally thought to be executed with rundll32. May grant fileless execution if victim endpoint has access to attacker-controlled SMB share.

## Usage
```powershell
rundll32.exe ExecIT.dll, HelperFunc, <path_to_file>
```

![poc](https://github.com/florylsk/ExecIT/assets/46110263/f4f13590-3ba7-45c3-a6a4-034f43b366a1)


## Detection

Currently it is fully undetected across all EDRs tested (depending on the shellcode) as of this commit.

E.g., for Defender for Endpoint EDR:


![image](https://github.com/florylsk/ExecIT/assets/46110263/a967f39b-027c-4bfa-b867-f6ec955ff54f)

## Disclaimer

The information/files provided in this repository are strictly intended for educational and ethical purposes only. The techniques and tools are intended to be used in a lawful and responsible manner, with the explicit consent of the target system's owner. Any unauthorized or malicious use of these techniques and tools is strictly prohibited and may result in legal consequences. I am not responsible for any damages or legal issues that may arise from the misuse of the information provided.
