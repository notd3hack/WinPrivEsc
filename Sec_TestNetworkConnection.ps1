<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛  

PowerShell script designed to detect anormality on computer (especially network connection)
Source (IP:PORT) and Destination (IP:PORT) and Process {NAME:ID} is visible
Run as Administrator for full process resolution
IR-NETWATCH  |  Incident Response TCP Connection Monitor
Researched by d3hack@VulnLab optimized with Sonnet 4.6
#>

$TRUSTED_PORTS   = @(80, 443, 53, 123)
$SUSPECT_PORTS   = @(4444, 1337, 31337, 8080, 8888, 9001, 6666, 6667, 1234)
$LOOPBACK_PREFIX = @('127.', '::1', '0.0.0.0')

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host ""
Write-Host "  IR-NETWATCH  |  TCP Established Connections  |  $timestamp" -ForegroundColor DarkCyan
Write-Host ""

Write-Host "  [CRIT] = Known C2 port or same local/remote port" -ForegroundColor Red
Write-Host "  [HIGH] = Non-standard remote port" -ForegroundColor Yellow
Write-Host "  [INFO] = Trusted port (80/443/53/123)" -ForegroundColor DarkGray
Write-Host ""

Write-Host ("  {0,-8} {1,-24} {2,-24} {3,-22} {4}" -f "SEV", "LOCAL", "REMOTE", "PROCESS", "REASON") -ForegroundColor DarkGray
Write-Host ("  " + ("-" * 95)) -ForegroundColor DarkGray

# Cache all processes once
$procTable = @{}
Get-Process | ForEach-Object { $procTable[$_.Id] = $_ }

$alerts = [System.Collections.Generic.List[object]]::new()

Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | ForEach-Object {
    $conn       = $_
    $localPort  = $conn.LocalPort
    $remotePort = $conn.RemotePort
    $remoteAddr = $conn.RemoteAddress
    $localAddr  = $conn.LocalAddress
    $pid_       = $conn.OwningProcess
    $proc       = $procTable[$pid_]
    $procName   = if ($proc) { "$($proc.ProcessName) ($pid_)" } else { "UNKNOWN ($pid_)" }

    # Skip loopback
    $isLoopback = $false
    foreach ($prefix in $LOOPBACK_PREFIX) {
        if ($remoteAddr.StartsWith($prefix)) { $isLoopback = $true; break }
    }
    if ($isLoopback) { return }

    # Severity logic
    $sev    = "INFO"
    $reason = "Trusted port"
    $fg     = "DarkGray"
    $bg     = $null

    if ($localPort -eq $remotePort) {
        $sev    = "CRIT"
        $reason = "Same local/remote port - anomalous"
        $fg     = "White"
        $bg     = "DarkRed"
    } elseif ($remotePort -in $SUSPECT_PORTS) {
        $sev    = "CRIT"
        $reason = "Known C2/backdoor port ($remotePort)"
        $fg     = "White"
        $bg     = "DarkRed"
    } elseif ($remotePort -notin $TRUSTED_PORTS) {
        $sev    = "HIGH"
        $reason = "Non-standard port ($remotePort)"
        $fg     = "Yellow"
        $bg     = $null
    }

    $line = "  {0,-8} {1,-24} {2,-24} {3,-22} {4}" -f `
        $sev,
        "$localAddr`:$localPort",
        "$remoteAddr`:$remotePort",
        $procName,
        $reason

    if ($bg) {
        Write-Host $line -ForegroundColor $fg -BackgroundColor $bg
    } else {
        Write-Host $line -ForegroundColor $fg
    }

    if ($sev -ne "INFO") {
        $alerts.Add([PSCustomObject]@{
            Severity   = $sev
            Remote     = "$remoteAddr`:$remotePort"
            Process    = $procName
            Reason     = $reason
        })
    }
}

# Summary block
Write-Host ""
Write-Host ("  " + ("-" * 95)) -ForegroundColor DarkGray
Write-Host ""

if ($alerts.Count -eq 0) {
    Write-Host "  [OK]  No suspicious connections detected." -ForegroundColor Green
} else {
    Write-Host "  [!!]  ALERT SUMMARY -- $($alerts.Count) connection(s) require attention:" -ForegroundColor Red
    Write-Host ""
    $alerts | ForEach-Object {
        $color = if ($_.Severity -eq "CRIT") { "Red" } else { "Yellow" }
        Write-Host "     [$($_.Severity)]  $($_.Remote)  ->  $($_.Process)" -ForegroundColor $color
        Write-Host "            > $($_.Reason)" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "  Scan complete: $timestamp" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  ACTIONS:" -ForegroundColor DarkCyan
Write-Host "  To kill a suspicious process by PID:" -ForegroundColor DarkGray
Write-Host "    Stop-Process -Id <PID> -Force" -ForegroundColor White
Write-Host "  To kill by name (all instances):" -ForegroundColor DarkGray
Write-Host "    Stop-Process -Name <ProcessName> -Force" -ForegroundColor White
Write-Host "  To block a remote IP via firewall:" -ForegroundColor DarkGray
Write-Host "    New-NetFirewallRule -DisplayName 'IR-Block' -Direction Outbound -RemoteAddress <IP> -Action Block" -ForegroundColor White
Write-Host "  To dump full connection details to CSV:" -ForegroundColor DarkGray
Write-Host "    Get-NetTCPConnection | Export-Csv -Path C:\IR\connections.csv -NoTypeInformation" -ForegroundColor White
Write-Host ""