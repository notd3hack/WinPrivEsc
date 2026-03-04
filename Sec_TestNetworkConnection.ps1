Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | ForEach-Object {
    $process = Get-Process -Id $_.OwningProcess
    Write-Host "Local: $($_.LocalAddress):$($_.LocalPort) | Remote: $($_.RemoteAddress):$($_.RemotePort) | Process: $($process.ProcessName) | PID: $($_.OwningProcess)"
}
