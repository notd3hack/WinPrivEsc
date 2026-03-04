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
Write-Host ("  {0,-8} {1,-24} {2,-24} {3,-18} {4,-8} {5}" -f "SEV", "LOCAL", "REMOTE", "PROCESS", "PID", "REASON") -ForegroundColor DarkGray
Write-Host ("  " + ("-" * 100)) -ForegroundColor DarkGray

# ============================================================
#  PROCESS CACHE
#  Layer 1 : Get-Process         (fast, user+admin processes)
#  Layer 2 : CIM Win32_Process   (fallback, catches system/svchost/idle)
# ============================================================
$procTable    = @{}   # PID -> [Name, Path]  via Get-Process
$cimTable     = @{}   # PID -> [Name, Path]  via CIM fallback

Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $path = try { $_.MainModule.FileName } catch { $null }
    $procTable[$_.Id] = [PSCustomObject]@{
        Name = $_.ProcessName
        Path = if ($path) { $path } else { $null }
    }
}

Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    $cimTable[$_.ProcessId] = [PSCustomObject]@{
        Name = $_.Name -replace '\.exe$', ''
        Path = if ($_.ExecutablePath) { $_.ExecutablePath } else { "Protected / System process" }
    }
}

function Resolve-Process {
    param([int]$PID_)

    if ($procTable.ContainsKey($PID_)) {
        $p    = $procTable[$PID_]
        $name = $p.Name
        $path = if ($p.Path) { $p.Path } `
                elseif ($cimTable.ContainsKey($PID_) -and $cimTable[$PID_].Path) { $cimTable[$PID_].Path } `
                else { "Path unavailable" }
        return $name, $path
    }

    if ($cimTable.ContainsKey($PID_)) {
        $c = $cimTable[$PID_]
        return $c.Name, $c.Path
    }

    $live = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $PID_" -ErrorAction SilentlyContinue
    if ($live) {
        $livePath = if ($live.ExecutablePath) { $live.ExecutablePath } else { "Protected / System process" }
        return ($live.Name -replace '\.exe$', ''), $livePath
    }

    return "UNKNOWN", "N/A"
}

$alerts = [System.Collections.Generic.List[object]]::new()


Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | ForEach-Object {
    $conn       = $_
    $localPort  = $conn.LocalPort
    $remotePort = $conn.RemotePort
    $remoteAddr = $conn.RemoteAddress
    $localAddr  = $conn.LocalAddress
    $pid_       = $conn.OwningProcess

    $procName, $procPath = Resolve-Process -PID_ $pid_

    $isLoopback = $false
    foreach ($prefix in $LOOPBACK_PREFIX) {
        if ($remoteAddr.StartsWith($prefix)) { $isLoopback = $true; break }
    }
    if ($isLoopback) { return }

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

    $line = "  {0,-8} {1,-24} {2,-24} {3,-18} {4,-8} {5}" -f `
        $sev,
        "$localAddr`:$localPort",
        "$remoteAddr`:$remotePort",
        $procName,
        $pid_,
        $reason

    if ($bg) {
        Write-Host $line -ForegroundColor $fg -BackgroundColor $bg
    } else {
        Write-Host $line -ForegroundColor $fg
    }

    $pathColor = if ($bg) { "White" } elseif ($sev -eq "HIGH") { "Yellow" } else { "DarkGray" }
    Write-Host ("           Path : $procPath") -ForegroundColor $pathColor

    if ($sev -ne "INFO") {
        $alerts.Add([PSCustomObject]@{
            Severity = $sev
            Remote   = "$remoteAddr`:$remotePort"
            ProcName = $procName
            ProcPath = $procPath
            PID      = $pid_
            Reason   = $reason
        })
    }
}


Write-Host ""
Write-Host ("  " + ("-" * 100)) -ForegroundColor DarkGray
Write-Host ""

if ($alerts.Count -eq 0) {
    Write-Host "  [OK]  No suspicious connections detected." -ForegroundColor Green
} else {
    Write-Host "  [!!]  ALERT SUMMARY -- $($alerts.Count) connection(s) require attention:" -ForegroundColor Red
    Write-Host ""
    $alerts | ForEach-Object {
        $color = if ($_.Severity -eq "CRIT") { "Red" } else { "Yellow" }
        Write-Host "     [$($_.Severity)]  $($_.Remote)" -ForegroundColor $color
        Write-Host "            > Process  : $($_.ProcName)  (PID: $($_.PID))" -ForegroundColor White
        Write-Host "            > Path     : $($_.ProcPath)" -ForegroundColor DarkGray
        Write-Host "            > Reason   : $($_.Reason)" -ForegroundColor DarkGray
        Write-Host "            > Kill     : Stop-Process -Id $($_.PID) -Force" -ForegroundColor DarkGray
        Write-Host ""
    }
}


Write-Host ("  " + ("-" * 100)) -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Scan complete: $timestamp" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  QUICK ACTIONS:" -ForegroundColor DarkCyan
Write-Host "  Kill process by PID   :  Stop-Process -Id <PID> -Force" -ForegroundColor White
Write-Host "  Kill process by name  :  Stop-Process -Name <ProcessName> -Force" -ForegroundColor White
Write-Host "  Block remote IP       :  New-NetFirewallRule -DisplayName 'IR-Block' -Direction Outbound -RemoteAddress <IP> -Action Block" -ForegroundColor White
Write-Host "  Export to CSV         :  Get-NetTCPConnection | Export-Csv -Path C:\IR\connections.csv -NoTypeInformation" -ForegroundColor White
Write-Host ""
Write-Host ("  " + ("-" * 100)) -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Window will stay open. Type 'exit' to close or close manually." -ForegroundColor DarkCyan
Write-Host ""