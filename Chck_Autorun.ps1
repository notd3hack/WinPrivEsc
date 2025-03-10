# Get Autorun Entries from Registry
$UserRun = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object -Property *
$MachineRun = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object -Property *

# Get Startup Folder Entries
$StartupFolder = Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" | Select-Object -Property Name, FullName

# Get Scheduled Tasks that Run on Login
$ScheduledTasks = Get-ScheduledTask | Where-Object { $_.Triggers -match 'Logon' } | Select-Object TaskName, State, Actions

# Display Results
Write-Output "`n[+] User Autorun Entries:"
$UserRun

Write-Output "`n[+] Machine Autorun Entries:"
$MachineRun

Write-Output "`n[+] Startup Folder Entries:"
$StartupFolder

Write-Output "`n[+] Scheduled Tasks (Logon Trigger):"
$ScheduledTasks