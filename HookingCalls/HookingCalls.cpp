#include <iostream>
#include <windows.h>
using namespace std;

int main()
{
    LPCWSTR appName = L".\\AppToHook.exe";
    char injectDLLName[] = ".\\HookDLL.dll";
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    wstring CommandLine(L"AppToHook.exe");

    LPWSTR lpwCmdLine = &CommandLine[0];

    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);

    if (!CreateProcess(NULL, lpwCmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        cout << "CreateProcess() failed. Error: " << GetLastError() << endl;
        return -1;
    }


    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pi.dwProcessId);
    if (process == NULL)
    {
        cout << "OpenProcess() failed. Error: " << GetLastError() << endl;
        return 1;
    }

    HMODULE hKernelModule = GetModuleHandle(TEXT("kernel32.dll"));
    if (hKernelModule == NULL)
    {
        cout << "GetModuleHandle() failed. Error: " << GetLastError() << endl;
        return 1;
    }

    FARPROC LoadLibraryAddress = GetProcAddress(hKernelModule, "LoadLibraryA");
    if (LoadLibraryAddress == NULL)
    {
        cout << "GetProcAddress() failed. Error: " << GetLastError() << endl;
        return 1;
    }

    PVOID rmMemory = VirtualAllocEx(process, NULL, strlen(injectDLLName) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (rmMemory == NULL)
    {
        cout << "VirtualAllocEx() failed. Error: " << GetLastError() << endl;
        return 1;
    }

    WriteProcessMemory(process, (LPVOID)rmMemory, injectDLLName, strlen(injectDLLName) + 1, NULL);
    HANDLE rmThread = CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, (LPVOID)rmMemory, NULL, NULL);
    if (rmThread == NULL)
    {
        cout << "CreateRemoteThread() failed. Error: " << GetLastError() << endl;
        return 1;
    }
    else {
        cout << "Injection complete" << endl;
    }

    ResumeThread(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
};