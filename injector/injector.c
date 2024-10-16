#include <stdio.h>
#include <windows.h>

#include "usage.h"
#include "arguments.h"

int main(int argc, char** argv)
{
    //
    // Argument handling
    //
    if (argc < 2)
    {
        fprintf(stdout, "%s", USAGE);
        return 1;
    }

    LPSTR CmdLine = GetCommandLineA();

    PROGRAMARGUMENTS args;
	ZeroMemory(&args, sizeof(PROGRAMARGUMENTS));
    for (unsigned int i = 1; i < (ULONG)argc; i++) {
        //
        // Iterate over argv and search for option.
        //
        if (strstr(argv[i], "-f")) {
            mSetArg(args.s_args, file);
            CmdLine = argv[i + 1];
        }
        if (strstr(argv[i], "-o")) mSetArg(args.s_args, output);
        if (strstr(argv[i], "--help") || strstr(argv[i], "-h")) {
            mSetArg(args.s_args, help);
            fprintf(stdout, "%s", USAGE);
            return 0;
        }
    }

    //
    // Check if "-f" was used at all.
    //
    if (!mCheckArg(args.s_args, file)) {
        fprintf(stdout, "%s", INVALID);
        return 1;
    }

    // No valid arguments were inputed
    if (args.s_args == 0) {
        fprintf(stderr, "%s", INVALID);
        return 1;
    }


    PROCESS_INFORMATION ProcessInformation;
    STARTUPINFOA StartupInfo;

    StartupInfo.cb = sizeof(STARTUPINFO);
    ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
    ZeroMemory(&ProcessInformation, sizeof(PROCESS_INFORMATION));

    //
    // Create the target process in suspended state.
    //
    if (!CreateProcessA(NULL, CmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInformation))
    {
        printf("[!] Failed to create the target process.\n[!] Error code: %u\n", GetLastError());
        return 1;
    }

    HANDLE hProcess = ProcessInformation.hProcess;
    HANDLE hThread = ProcessInformation.hThread;

    //
    // Check if the target process is a Wow64 process and if so, terminate it cause we don't support it for now.
    //
#ifdef _WIN64
    BOOL IsWow64Proc = FALSE;

    if (!IsWow64Process(hProcess, &IsWow64Proc))
    {
        printf("[!] Failed to check if the target process is WoW64.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    if (IsWow64Proc)
    {
        printf("[!] The target file needs to be a x64 file.\n");
        TerminateProcess(hProcess, 0);
        return 1;
    }
#endif

    char LibFullPath[MAX_PATH] = {0};
    char CurrentModuleFilepath[MAX_PATH] = {0};

    DWORD Len = GetModuleFileNameA(GetModuleHandleA(NULL), CurrentModuleFilepath, MAX_PATH);

    if (!Len)
    {
        printf("[!] Failed to get the current module filepath.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    for (SIZE_T i = Len - 1; i > 0; i--)
    {
        if (CurrentModuleFilepath[i] == 0x5c || CurrentModuleFilepath[i] == 0x2f)
        {
            CurrentModuleFilepath[i + 1] = '\0';
            break;
        }
    }

    SIZE_T i = 0;

    do
    {
        LibFullPath[i] = CurrentModuleFilepath[i];
        i++;
    } while (CurrentModuleFilepath[i] != '\0');

#ifdef _WIN64
    const char* LibName = "\\gftrace.dll";
#else
    const char* LibName = "\\gftrace32.dll";
#endif

    SIZE_T Size = strlen(LibFullPath) + strlen(LibName) + 1;

    //
    // Build the gftrace.dll full path to be used in the injection step.
    //
    strncat_s(LibFullPath, Size, LibName, _TRUNCATE);

    //
    // Check if the gftrace.dll file exists in the gftrace.exe directory.
    //
    if (GetFileAttributesA((LPCSTR)LibFullPath) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND)
    {
        printf("[!] Failed to find the gftrace DLL file in the gftrace.exe directory.\n");
        TerminateProcess(hProcess, 0);
        return 1;
    }

    //
    // Get kernel32.dll module base address.
    //
    HMODULE ModuleBase = GetModuleHandleW(L"kernel32.dll");

    if (ModuleBase == NULL)
    {
        printf("[!] Failed to get kernel32 base address.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    //
    // Get the address of LoadLibraryA() to be used to inject gftrace DLL into the target process.
    //
    FARPROC pLoadLibraryA = GetProcAddress(ModuleBase, "LoadLibraryA");

    if (pLoadLibraryA == NULL)
    {
        printf("[!] Failed to resolve LoadLibraryA address.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    //
    // Allocate memory for gftrace DLL full path in the target process.
    //
    LPVOID LibFullPathRemoteAddr = VirtualAllocEx(hProcess, NULL, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (LibFullPathRemoteAddr == NULL)
    {
        printf("[!] Failed to allocate virtual memory in the target process.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    //
    // Write gftrace DLL full path into the target process.
    //
    if (!WriteProcessMemory(hProcess, LibFullPathRemoteAddr, (LPCVOID)LibFullPath, Size, NULL))
    {
        printf("[!] Failed to write to the target process memory.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    DWORD ThreadId;

    //
    // Create a thread in the target process pointing to LoadLibraryA() to load the gftrace DLL into the target process address space.
    //
    HANDLE hInjectionThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, (LPVOID)LibFullPathRemoteAddr, 0, &ThreadId);

    if (hInjectionThread == NULL)
    {
        printf("[!] Failed to create a remote thread in the target process.\n[!] Error code: %u\n", GetLastError());
        TerminateProcess(hProcess, 0);
        return 1;
    }

    //
    // Wait for the injection thread to finish.
    //
    WaitForSingleObject(hInjectionThread, INFINITE);

    //
    // Resume the target process main thread.
    //
    ResumeThread(hThread);

    WaitForSingleObject(hProcess, INFINITE);

    VirtualFreeEx(hProcess, LibFullPathRemoteAddr, 0, MEM_RELEASE);
    CloseHandle(hInjectionThread);
    CloseHandle(hThread);

    return 0;
}