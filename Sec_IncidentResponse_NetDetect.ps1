<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛  

PowerShell script designed to detect anomalies on computer (especially network connections)
Source (IP:PORT) and Destination (IP:PORT) and Process {NAME:ID} is visible
IR-NETWATCH  |  Incident Response TCP Connection Monitor
Researched by d3hack@VulnLab optimized with Sonnet 4.6
#>

# ============================================================
#  SELF-ELEVATE -- relaunches as Admin, stays open after scan
# ============================================================
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "  [!!] Not running as Administrator. Requesting elevation..." -ForegroundColor Yellow
    Write-Host ""
    Start-Process powershell.exe `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`"" `
        -Verb RunAs `
        -Wait
    exit
}

# ============================================================
#  CONFIGURATION
# ============================================================
$TRUSTED_PORTS   = @(80, 443, 53, 123)
$SUSPECT_PORTS   = @(4444, 1337, 31337, 8080, 8888, 9001, 6666, 6667, 1234)
$LOOPBACK_PREFIX = @('127.', '::1', '0.0.0.0')

# ============================================================
#  HEADER
# ============================================================
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

# ============================================================
#  PROCESS CACHE  (single lookup, faster than per-connection)
# ============================================================
$procTable = @{}
Get-Process | ForEach-Object { $procTable[$_.Id] = $_ }

$alerts = [System.Collections.Generic.List[object]]::new()

# ============================================================
#  MAIN SCAN
# ============================================================
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | ForEach-Object {
    $conn       = $_
    $localPort  = $conn.LocalPort
    $remotePort = $conn.RemotePort
    $remoteAddr = $conn.RemoteAddress
    $localAddr  = $conn.LocalAddress
    $pid_       = $conn.OwningProcess
    $proc       = $procTable[$pid_]
    $procName   = if ($proc) { "$($proc.ProcessName) ($pid_)" } else { "UNKNOWN ($pid_)" }

    # Skip loopback -- not useful during IR
    $isLoopback = $false
    foreach ($prefix in $LOOPBACK_PREFIX) {
        if ($remoteAddr.StartsWith($prefix)) { $isLoopback = $true; break }
    }
    if ($isLoopback) { return }

    # Severity classification
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
            Severity = $sev
            Remote   = "$remoteAddr`:$remotePort"
            Process  = $procName
            PID      = $pid_
            Reason   = $reason
        })
    }
}

# ============================================================
#  ALERT SUMMARY
# ============================================================
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
        Write-Host "            > Kill: Stop-Process -Id $($_.PID) -Force" -ForegroundColor DarkGray
    }
}

# ============================================================
#  FOOTER + QUICK ACTIONS
# ============================================================
Write-Host ""
Write-Host "  Scan complete: $timestamp" -ForegroundColor DarkCyan
Write-Host ""
Write-Host ("  " + ("-" * 95)) -ForegroundColor DarkGray
Write-Host ""
Write-Host "  QUICK ACTIONS:" -ForegroundColor DarkCyan
Write-Host "  Kill process by PID   :  Stop-Process -Id <PID> -Force" -ForegroundColor White
Write-Host "  Kill process by name  :  Stop-Process -Name <ProcessName> -Force" -ForegroundColor White
Write-Host "  Block remote IP       :  New-NetFirewallRule -DisplayName 'IR-Block' -Direction Outbound -RemoteAddress <IP> -Action Block" -ForegroundColor White
Write-Host "  Export to CSV         :  Get-NetTCPConnection | Export-Csv -Path C:\IR\connections.csv -NoTypeInformation" -ForegroundColor White
Write-Host ""
Write-Host ("  " + ("-" * 95)) -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Window will stay open. Type 'exit' to close or close manually." -ForegroundColor DarkCyan
Write-Host ""