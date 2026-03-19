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

Detection layers:
  - Standard port-based triage    (CRIT/HIGH/INFO)
  - LOLBin outbound connections   (rundll32, mshta, wscript, cscript, certutil, regsvr32 ...)
  - Suspicious svchost.exe        (wrong path, or making direct outbound connections)
  - WMI service abuse             (WmiPrvSE, wmiprvse making outbound connections)
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

$LOLBINS = @(
    'rundll32', 'mshta', 'wscript', 'cscript', 'regsvr32',
    'certutil', 'bitsadmin', 'msiexec', 'installutil',
    'regasm', 'regsvcs', 'cmstp', 'msbuild', 'msconfig',
    'eudcedit', 'odbcconf', 'ieexec', 'pcalua'
)

$LEGIT_SVCHOST_PATH = "$env:SystemRoot\System32\svchost.exe"

$WMI_PROCS = @('WmiPrvSE', 'wmiprvse', 'WmiApSrv', 'wbemcons', 'unsecapp')

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host ""
Write-Host "  IR-NETWATCH  |  TCP Established Connections  |  $timestamp" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  [CRIT] = Known C2 port / same-port / LOLBin / rogue svchost / WMI abuse" -ForegroundColor Red
Write-Host "  [HIGH] = Non-standard remote port" -ForegroundColor Yellow
Write-Host "  [INFO] = Trusted port (80/443/53/123)" -ForegroundColor DarkGray
Write-Host ""
Write-Host ("  {0,-8} {1,-24} {2,-24} {3,-18} {4,-8} {5}" -f `
    "SEV", "LOCAL", "REMOTE", "PROCESS", "PID", "REASON") -ForegroundColor DarkGray
Write-Host ("  " + ("-" * 100)) -ForegroundColor DarkGray

$procTable = @{}
$cimTable  = @{}

Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $path = try { $_.MainModule.FileName } catch { $null }
    $procTable[$_.Id] = [PSCustomObject]@{
        Name   = $_.ProcessName
        Path   = $path
    }
}

Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    $cimTable[$_.ProcessId] = [PSCustomObject]@{
        Name     = $_.Name -replace '\.exe$', ''
        Path     = if ($_.ExecutablePath) { $_.ExecutablePath } else { "Protected / System process" }
        ParentId = $_.ParentProcessId
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
        $parentId = if ($cimTable.ContainsKey($PID_)) { $cimTable[$PID_].ParentId } else { $null }
        return $name, $path, $parentId
    }

    if ($cimTable.ContainsKey($PID_)) {
        $c = $cimTable[$PID_]
        return $c.Name, $c.Path, $c.ParentId
    }

    $live = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $PID_" -ErrorAction SilentlyContinue
    if ($live) {
        $livePath = if ($live.ExecutablePath) { $live.ExecutablePath } else { "Protected / System process" }
        return ($live.Name -replace '\.exe$', ''), $livePath, $live.ParentProcessId
    }

    return "UNKNOWN", "N/A", $null
}

$servicesPID = (Get-CimInstance -ClassName Win32_Process -Filter "Name = 'services.exe'" -ErrorAction SilentlyContinue).ProcessId

$alerts = [System.Collections.Generic.List[object]]::new()

Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | ForEach-Object {
    $conn       = $_
    $localPort  = $conn.LocalPort
    $remotePort = $conn.RemotePort
    $remoteAddr = $conn.RemoteAddress
    $localAddr  = $conn.LocalAddress
    $pid_       = $conn.OwningProcess

    $procName, $procPath, $parentId = Resolve-Process -PID_ $pid_

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

    } elseif ($procName -in $LOLBINS) {
        $sev    = "CRIT"
        $reason = "LOLBin outbound connection - $procName should NOT connect"
        $fg     = "White"
        $bg     = "DarkRed"

    } elseif ($procName -eq 'svchost') {
        if ($procPath -ne "Protected / System process" -and
            $procPath -ne "Path unavailable" -and
            $procPath -notlike "*\System32\svchost.exe") {
            $sev    = "CRIT"
            $reason = "svchost running from WRONG PATH - possible hollowing"
            $fg     = "White"
            $bg     = "DarkRed"
        } elseif ($servicesPID -and $parentId -and $parentId -ne $servicesPID) {
            $sev    = "CRIT"
            $reason = "svchost parent is NOT services.exe (PID:$parentId) - suspicious"
            $fg     = "White"
            $bg     = "DarkRed"
        } else {
            $sev    = "CRIT"
            $reason = "svchost making direct outbound connection - investigate"
            $fg     = "White"
            $bg     = "DarkRed"
        }

    } elseif ($procName -in $WMI_PROCS) {
        $sev    = "CRIT"
        $reason = "WMI process outbound - possible WMI-based C2 / lateral movement"
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
            ParentId = $parentId
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
        Write-Host "            > Parent   : PID $($_.ParentId)" -ForegroundColor DarkGray
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
Write-Host "  Kill process by PID      :  Stop-Process -Id <PID> -Force" -ForegroundColor White
Write-Host "  Kill process by name     :  Stop-Process -Name <ProcessName> -Force" -ForegroundColor White
Write-Host "  Block remote IP          :  New-NetFirewallRule -DisplayName 'IR-Block' -Direction Outbound -RemoteAddress <IP> -Action Block" -ForegroundColor White
Write-Host "  Export to CSV            :  Get-NetTCPConnection | Export-Csv -Path C:\IR\connections.csv -NoTypeInformation" -ForegroundColor White
Write-Host "  Check parent of PID      :  Get-CimInstance Win32_Process -Filter 'ProcessId=<PID>' | Select Name,ParentProcessId,ExecutablePath" -ForegroundColor White
Write-Host "  List services for svchost:  tasklist /svc /fi 'PID eq <PID>'" -ForegroundColor White
Write-Host ""
Write-Host ("  " + ("-" * 100)) -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Window will stay open. Type 'exit' to close or close manually." -ForegroundColor DarkCyan
Write-Host ""