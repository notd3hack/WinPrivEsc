# Supply Chain Attack simulation for Security Research
## Scenario

| IP Range for LAB's     | 10.10.10.100 to 10.10.10.200 |
| ---------------------- | ---------------------------- |
| DC IP                  | 10.10.10.100 or 10.10.10.150 |
| Ubuntu (Update) Server | 10.10.10.175                 |




Stage 1:
 Attacker gaining unauthorized access to Ubuntu Server or impersonating IP Address.
Stage 2: 
 Attacker creating `beacon.dll` and rename as `component.dll` to replace legit component
Stage 3:
 User procedures update and attacker gaining access Windows Machine


### Service (Basic Program With Tray Icon not a Win32_Service) 
**vulnservice.c**
```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#define WM_TRAYICON (WM_APP + 1)
#define ID_TRAYICON  1

// Global variables
NOTIFYICONDATA nid = {0};
HWND hMainWnd;
HINSTANCE hInst;

// Forward declarations
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void InitTrayIcon(HWND hwnd);
void ShowMainWindow(HWND hwnd);
void HideMainWindow(HWND hwnd);

// Entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    hInst = hInstance;

    // Load the component DLL (message box will be shown here)
    HMODULE hComp = LoadLibrary("component.dll");
    if (!hComp) {
        MessageBox(NULL, "component.dll not found!", "VulnService Error", MB_ICONERROR);
        return 1;
    }

    // Register window class
    WNDCLASSEX wc = {0};
    wc.cbSize        = sizeof(WNDCLASSEX);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "VulnCorpClass";
    RegisterClassEx(&wc);

    // Create a small window (bottom‑right corner)
    int width = 280, height = 150;
    int x = GetSystemMetrics(SM_CXSCREEN) - width - 20;
    int y = GetSystemMetrics(SM_CYSCREEN) - height - 50;

    hMainWnd = CreateWindowEx(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        "VulnCorpClass", "VulnCorp Anticheat",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        x, y, width, height,
        NULL, NULL, hInstance, NULL);

    if (!hMainWnd) return 1;

    // Add "Update" button
    CreateWindow("BUTTON", "Check for Updates",
                 WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                 70, 50, 140, 30,
                 hMainWnd, (HMENU)1001, hInstance, NULL);

    // Status text
    CreateWindow("STATIC", "Service running...",
                 WS_CHILD | WS_VISIBLE | SS_CENTER,
                 70, 20, 140, 20,
                 hMainWnd, NULL, hInstance, NULL);

    // Tray icon
    InitTrayIcon(hMainWnd);

    // Start hidden (show tray icon only)
    ShowWindow(hMainWnd, SW_HIDE);

    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    FreeLibrary(hComp);
    return (int)msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_COMMAND:
        if (LOWORD(wParam) == 1001) {  // Update button
            // Launch updater.exe
            ShellExecute(NULL, "open", "updater.exe", NULL, NULL, SW_SHOWNORMAL);
        }
        break;

    case WM_CLOSE:
        HideMainWindow(hwnd);
        return 0;  // Don’t destroy

    case WM_DESTROY:
        Shell_NotifyIcon(NIM_DELETE, &nid);
        PostQuitMessage(0);
        break;

    case WM_TRAYICON:
        if (lParam == WM_LBUTTONDBLCLK) {
            ShowMainWindow(hwnd);
        }
        break;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void InitTrayIcon(HWND hwnd)
{
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = ID_TRAYICON;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);  // placeholder icon
    lstrcpy(nid.szTip, "VulnCorp Service");
    Shell_NotifyIcon(NIM_ADD, &nid);
}

void ShowMainWindow(HWND hwnd)
{
    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
}

void HideMainWindow(HWND hwnd)
{
    ShowWindow(hwnd, SW_HIDE);
}
```


### Dependency (Component.dll)
**component.c** 
```c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        MessageBox(NULL,
                   "You Using VulnCorp Software",
                   "VulnCorp Component",
                   MB_OK | MB_ICONINFORMATION);
    }
    return TRUE;
}
```

### Software updater
**updater.c**
```c
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

#define SERVER_HOST L"10.10.10.175"
#define SERVER_PORT 8298
#define DLL_PATH     L"C:\\Program Files\\VulnService\\component.dll"
#define TEMP_PATH    L"C:\\Program Files\\VulnService\\component.tmp"

// Simple function to print coloured status
void SetStatus(const char* text, const char* color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (color) {
        // Use ANSI escape codes (works on Win10+)
        printf("\033[%sm%s\033[0m\n", color, text);
    } else {
        printf("%s\n", text);
    }
}

// Download file from HTTP server
BOOL DownloadFile(LPCWSTR host, INTERNET_PORT port, LPCWSTR path, LPCWSTR localPath) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL result = FALSE;
    DWORD dwSize = 0;
    LPBYTE pBuffer = NULL;
    DWORD dwDownloaded = 0;

    hSession = WinHttpOpen(L"VulnCorp Updater/1.0",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto cleanup;

    hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect) goto cleanup;

    hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
                                  NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) goto cleanup;

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        goto cleanup;

    if (!WinHttpReceiveResponse(hRequest, NULL))
        goto cleanup;

    // Read data in chunks
    HANDLE hFile = CreateFileW(localPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto cleanup;

    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            break;
        if (dwSize == 0) break;

        pBuffer = (LPBYTE)LocalAlloc(LPTR, dwSize);
        if (!pBuffer) break;

        if (!WinHttpReadData(hRequest, pBuffer, dwSize, &dwDownloaded))
            break;

        DWORD written = 0;
        WriteFile(hFile, pBuffer, dwDownloaded, &written, NULL);

        LocalFree(pBuffer);
        pBuffer = NULL;
    } while (dwSize > 0);

    CloseHandle(hFile);
    result = TRUE;

cleanup:
    if (pBuffer) LocalFree(pBuffer);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return result;
}

// Kill a process by name
void KillProcess(const char* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    TerminateProcess(hProc, 0);
                    CloseHandle(hProc);
                }
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

int main() {
    // Enable UTF-8 for emoji output
    SetConsoleOutputCP(CP_UTF8);

    // 🟡 Yellow – Checking…
    SetStatus(" Checking…", "33");  // 33 = yellow

    // Download the new DLL
    if (!DownloadFile(SERVER_HOST, SERVER_PORT, L"/component.dll", TEMP_PATH)) {
        // 🔴 Red – Offline
        SetStatus(" Offline", "31");
        return 1;
    }

    // 🟢 Green – Online
    SetStatus(" Online", "32");

    // Stop VulnService
    printf("Stopping VulnService...\n");
    KillProcess("VulnService.exe");
    Sleep(1000);  // wait for process to exit

    // Replace the DLL
    if (!CopyFileW(TEMP_PATH, DLL_PATH, FALSE)) {
        printf("Failed to replace component.dll (try running as Administrator).\n");
        DeleteFileW(TEMP_PATH);
        return 1;
    }
    DeleteFileW(TEMP_PATH);

    // Restart the service
    printf("Restarting VulnService...\n");
    ShellExecuteW(NULL, L"open", L"C:\\Program Files\\VulnService\\VulnService.exe",
                  NULL, NULL, SW_HIDE);

    return 0;
}
```

### Compilation (Kali Linux 2026)
```bash
sudo apt update
sudo apt install mingw-w64
x86_64-w64-mingw32-gcc -shared -o component.dll component.c -s
x86_64-w64-mingw32-gcc -o VulnService.exe vulnservice.c -mwindows -s
x86_64-w64-mingw32-gcc -o updater.exe updater.c -lwinhttp -s
```


### Malicious dependency
```c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        MessageBox(NULL,
                   "Hacked! Supply chain successful.",
                   "VulnCorp Component",
                   MB_OK | MB_ICONWARNING);
    }
    return TRUE;
}
```


### Remember
Software must be installed on "C:\Program Files\VulnService" folder. Also. VulnService.exe need to run as a Administrator for full simulation.


```powershell
PS C:\Program Files\VulnService> dir


    Directory: C:\Program Files\VulnService


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/15/2026   2:24 AM          12288 component.dll
-a----         5/15/2026   2:23 AM          46592 updater.exe
-a----         5/15/2026   2:23 AM          17920 VulnService.exe


PS C:\Program Files\VulnService>
```