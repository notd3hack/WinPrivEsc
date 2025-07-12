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
    MessageBoxA(0, "Your syscall working successfully!", "VulnCorp", MB_OK);
    
    system("cmd.exe /c whoami > C:\\Windows\\Temp\\unquoted_path_result.txt");
    
    return 0;
}