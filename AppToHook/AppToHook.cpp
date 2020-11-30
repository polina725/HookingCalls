#include <iostream>
#include <windows.h>
#define REG_PATH L"Software\\TestApplication"
using namespace std;

int main()
{
    HANDLE file = CreateFile(L"test.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    string data = "Goin' up, goin' down, in and out, turn around";
    WriteFile(file, data.c_str(), data.size(), NULL, NULL);
    SetFilePointer(file, 0, NULL, FILE_BEGIN);

    char buf[50];
    DWORD bufSize = sizeof(buf);
    ZeroMemory(&buf, sizeof(buf));
    ReadFile(file, buf, data.size(), NULL, NULL);//45

    CloseHandle(file);
    DeleteFile(L"test.txt");
    Sleep(50);
    HKEY result;
    RegOpenKey(HKEY_CURRENT_USER, L"Software\\Adobe", &result);
    RegCloseKey(result);

    HKEY createResult;
    RegCreateKey(HKEY_CURRENT_USER, REG_PATH, &createResult);
    LPCWSTR lpData = L"test-data";
    RegSetValue(HKEY_CURRENT_USER, REG_PATH, REG_SZ, lpData, sizeof(wchar_t) * (wcslen(lpData) + 1));
    RegCloseKey(createResult);
    RegDeleteKey(HKEY_CURRENT_USER, REG_PATH);
    cout << "Marker\n";
    return 0;
}