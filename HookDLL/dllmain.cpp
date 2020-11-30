// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include ".\include\detours.h"
#include <iostream>
#include <fstream>
#include <sstream>
#pragma comment(lib,"detours.lib")
using namespace std;

HANDLE hStdOut;
wofstream outputFile;

HANDLE(WINAPI* pCreateFile) (LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFile;
BOOL(WINAPI* pReadFile) (HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
LSTATUS(WINAPI* pRegSetValue) (HKEY, LPCWSTR, DWORD, LPCWSTR, DWORD) = RegSetValue;
LONG(WINAPI* pRegOpenKey) (HKEY, LPCWSTR, PHKEY) = RegOpenKey;
LSTATUS(WINAPI* pRegCloseKey) (HKEY) = RegCloseKey;
BOOL(WINAPI* pDeleteFile) (LPCWSTR) = DeleteFile;
LSTATUS(WINAPI* pRegDeleteKey) (HKEY hKey, LPCWSTR lpSubKey) = RegDeleteKey;
LSTATUS(WINAPI* pRegCreateKey) (HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) = RegCreateKey;

VOID displayMessage(wstring);
VOID writeToLogFile(wstring);

HANDLE WINAPI hookCreateFile(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
BOOL WINAPI hookReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL WINAPI hookDeleteFile(LPCWSTR);
LSTATUS WINAPI hookRegSetValue(HKEY, LPCWSTR, DWORD, LPCWSTR, DWORD);
LONG WINAPI hookRegOpenKey(HKEY, LPCWSTR, PHKEY);
LSTATUS WINAPI hookRegCloseKey(HKEY);
LSTATUS WINAPI hookRegDeleteKey(HKEY, LPCWSTR);
LSTATUS WINAPI hookRegCreateKey(HKEY, LPCWSTR, PHKEY);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

        TCHAR str[MAX_PATH] = { 0 };
        GetModuleFileName(hModule, str, MAX_PATH);
        WCHAR sep = '/';

#ifdef _WIN32
        sep = '\\';
#endif
        std::wstring::size_type pos = std::wstring(str).find_last_of(sep);// L"\\/"
        wstring path = wstring(str).substr(0, pos);
        outputFile.open(path + L"\\log_1.txt");

        DisableThreadLibraryCalls(hModule);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach(&(PVOID&)pCreateFile, hookCreateFile);
        DetourAttach(&(PVOID&)pReadFile, hookReadFile);
        DetourAttach(&(PVOID&)pDeleteFile, hookDeleteFile);
        DetourAttach(&(PVOID&)pRegSetValue, hookRegSetValue);
        DetourAttach(&(PVOID&)pRegOpenKey, hookRegOpenKey);
        DetourAttach(&(PVOID&)pRegCloseKey, hookRegCloseKey);
        DetourAttach(&(PVOID&)pRegCreateKey, hookRegCreateKey);

        DetourTransactionCommit();
    }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach(&(PVOID&)pCreateFile, hookCreateFile);
        DetourDetach(&(PVOID&)pReadFile, hookReadFile);
        DetourDetach(&(PVOID&)pDeleteFile, hookDeleteFile);
        DetourDetach(&(PVOID&)pRegSetValue, hookRegSetValue);
        DetourDetach(&(PVOID&)pRegOpenKey, hookRegOpenKey);
        DetourDetach(&(PVOID&)pRegCloseKey, hookRegCloseKey);
        DetourDetach(&(PVOID&)pRegCreateKey, hookRegCreateKey);

        DetourTransactionCommit();

        CloseHandle(hStdOut);
        break;
    }
    return TRUE;
}

HANDLE WINAPI hookCreateFile(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    wostringstream message;
    message << L"CreateFile() was called. File name: " << (wstring)lpFileName << L"\n";
    displayMessage(message.str());
    writeToLogFile(message.str());
    return pCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI hookReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    wostringstream message;
    message << L"ReadFile() was called. Bytes to read: " << nNumberOfBytesToRead << L"\n";
    displayMessage(message.str());
    writeToLogFile(message.str());
    return pReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

LSTATUS WINAPI hookRegSetValue(HKEY hKey, LPCWSTR lpSubKey, DWORD dwType, LPCWSTR lpData, DWORD cbData) {
    wostringstream message;
    message << L"RegSetValue() was called. Subkey: " << (wstring)lpSubKey << L". Data: " << (wstring)lpData << L"\n";
    displayMessage(message.str());
    writeToLogFile(message.str());
    return pRegSetValue(hKey, lpSubKey, dwType, lpData, cbData);
}

LONG WINAPI hookRegOpenKey(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) {
    wostringstream message;
    message << L"RegOpenKey() was called. Subkey: " << (wstring)lpSubKey << L"\n";
    displayMessage(message.str());
    writeToLogFile(message.str());
    return pRegOpenKey(hKey, lpSubKey, phkResult);
}

LSTATUS WINAPI hookRegCloseKey(HKEY hKey) {
    wostringstream message;
    message << L"RegCloseKey() was called.\n";
    displayMessage(message.str());
    writeToLogFile(message.str());
    return pRegCloseKey(hKey);
}

BOOL WINAPI hookDeleteFile(LPCWSTR lpFileName)
{
    wostringstream message;
    message << L"DeleteFile() was called. File name: " << (wstring)lpFileName << L"\n";
    displayMessage(message.str());
    writeToLogFile(message.str());
    return pDeleteFile(lpFileName);
}

LSTATUS WINAPI hookRegDeleteKey(HKEY hKey, LPCWSTR lpSubKey)
{
    wostringstream message;
    message << L"RegDeleteKey() was called. Subkey: " << (wstring)lpSubKey << L"\n";
    displayMessage(message.str());
    writeToLogFile(message.str());
    return pRegDeleteKey(hKey, lpSubKey);
}

LSTATUS WINAPI hookRegCreateKey(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult)
{
    wostringstream message;
    message << L"RegCreateKey() was called. Subkey: " << (wstring)lpSubKey << L"\n";
    displayMessage(message.str());
    writeToLogFile(message.str());
    return pRegCreateKey(hKey, lpSubKey, phkResult);
}

VOID displayMessage(wstring message)
{
    if (hStdOut != NULL) {
        WriteConsole(hStdOut, message.c_str(), message.size(), NULL, NULL);

    }
}

VOID writeToLogFile(wstring message) {
    if (outputFile.is_open()) {
        outputFile << message << endl;
        outputFile.flush();
    }
}