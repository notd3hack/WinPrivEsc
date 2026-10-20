<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛          

USAGE: first click RAW button and copy link above
irm <github-raw-link> | iex             
irm is short for Invoke-RestMethod. 
It will download a script from that website. 
iex is short for Invoke-Expression. 
It will run the script

Cross-compatible security audit for Windows 11 25H2 and Windows Server 2025.
Runs on PowerShell 7+ with PwshSpectreConsole (auto-detected) and on
Windows PowerShell 5.1 with a classic color-coded fallback renderer.

NOTE ON ENCODING:
This script is pure ASCII. Save it with any encoding (ANSI, UTF-8 with BOM,
or UTF-8 without BOM). Do NOT paste non-ASCII characters (em dashes,
smart quotes, the ampersand in prose) into it - they will break string
parsing on Windows PowerShell 5.1 which reads UTF-8-without-BOM as ANSI.

.\Check_PotentialVectorEnum.ps1
.\Check_PotentialVectorEnum.ps1 -OutputFormat Json -OutputPath .\audit.json
#>

[CmdletBinding()]
param(
    [ValidateSet('Console','Json','Csv')]
    [string]$OutputFormat = 'Console',

    [string]$OutputPath
)


$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:UseSpectre = $false

if ($PSVersionTable.PSVersion.Major -ge 7) {
    try {
        Import-Module PwshSpectreConsole -ErrorAction Stop
        $script:UseSpectre = $true
    } catch {
        Write-Warning 'PwshSpectreConsole not found. Falling back to classic console output.'
    }
}

function Add-Finding {
    param(
        [string]$Severity,
        [string]$Message,
        [string]$Category = 'General',
        [string]$Detail   = ''
    )
    $script:Findings.Add([PSCustomObject]@{
        Severity  = $Severity
        Category  = $Category
        Message   = $Message
        Detail    = $Detail
        Timestamp = (Get-Date -Format 'o')
    })
}


function Write-Info {
    param([string]$Message, [string]$Category = 'Info')
    if ($script:UseSpectre) {
        Write-SpectreHost "[cyan][*][/] $Message"
    } else {
        Write-Host "[*] $Message" -ForegroundColor Cyan
    }
    Add-Finding -Severity 'Info' -Message $Message -Category $Category
}

function Write-Good {
    param([string]$Message, [string]$Category = 'General')
    if ($script:UseSpectre) {
        Write-SpectreHost "[green][+][/] $Message"
    } else {
        Write-Host "[+] $Message" -ForegroundColor Green
    }
    Add-Finding -Severity 'Good' -Message $Message -Category $Category
}

function Write-Warn {
    param([string]$Message, [string]$Category = 'General')
    if ($script:UseSpectre) {
        Write-SpectreHost "[yellow][!][/] $Message"
    } else {
        Write-Host "[!] $Message" -ForegroundColor Yellow
    }
    Add-Finding -Severity 'Warn' -Message $Message -Category $Category
}

function Write-Bad {
    param([string]$Message, [string]$Category = 'General')
    if ($script:UseSpectre) {
        Write-SpectreHost "[red][X][/] $Message"
    } else {
        Write-Host "[X] $Message" -ForegroundColor Red
    }
    Add-Finding -Severity 'Bad' -Message $Message -Category $Category
}

function Write-Separator {
    if ($script:UseSpectre) {
        Write-SpectreRule -Title '' -Color DarkGray
    } else {
        Write-Host ('-' * 80) -ForegroundColor DarkGray
    }
}

function Write-SectionHeader {
    param([string]$Title)
    if ($script:UseSpectre) {
        Write-SpectreRule -Title "[bold white]$Title[/]" -Color DarkGray -Alignment Left
    } else {
        Write-Host ''
        Write-Host "-- $Title --" -ForegroundColor White
    }
}


function Get-CurrentUser {
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

function Test-AdminRights {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PathWriteable {
    param([string]$Path)
    try {
        $acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue
        if (-not $acl) { return $false }
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -ne 'Allow') { continue }
            $idRef = $rule.IdentityReference.Value
            if ($idRef -in @('BUILTIN\Users','NT AUTHORITY\Authenticated Users',$identity.Name) -and
                $rule.FileSystemRights -match 'Write|Modify|FullControl') {
                return $true
            }
        }
        return ($acl.Owner -eq $identity.User -or $acl.Owner -eq 'BUILTIN\Users')
    } catch { return $false }
}

function Test-RegistryKeyWriteable {
    param([string]$Path)
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path, $true)
        if ($null -ne $key) { $key.Close(); return $true }
        return $false
    } catch { return $false }
}

function Check-Hotfix {
    param([string]$KB)
    return $null -ne (Get-HotFix -Id $KB -ErrorAction SilentlyContinue)
}

function ConvertTo-AccessMask {
    param([string]$permStr)
    if ($permStr -match '^0x') { return [Convert]::ToUInt32($permStr, 16) }
    if ($permStr -match '^\d+$') { return [Convert]::ToUInt32($permStr, 10) }
    $map = @{
        'CC'=0x2; 'DC'=0x4; 'LC'=0x8; 'SW'=0x10; 'RP'=0x20; 'WP'=0x40
        'DT'=0x80; 'LO'=0x100; 'CR'=0x200; 'GA'=0xF01FF; 'WD'=0x10000
        'WO'=0x20000; 'SD'=0x40000; 'RC'=0x20000
    }
    $mask = 0; $i = 0
    while ($i -lt $permStr.Length) {
        $matched = $false
        foreach ($key in $map.Keys | Sort-Object Length -Descending) {
            if ($permStr.Substring($i).StartsWith($key)) {
                $mask = $mask -bor $map[$key]; $i += $key.Length; $matched = $true; break
            }
        }
        if (-not $matched) { $i++ }
    }
    return $mask
}

function Get-HumanReadableServiceRights {
    param([UInt32]$mask)
    $rights = @()
    if ($mask -band 0x1)    { $rights += 'SERVICE_QUERY_CONFIG' }
    if ($mask -band 0x2)    { $rights += 'SERVICE_CHANGE_CONFIG' }
    if ($mask -band 0x4)    { $rights += 'SERVICE_QUERY_STATUS' }
    if ($mask -band 0x8)    { $rights += 'SERVICE_ENUMERATE_DEPENDENTS' }
    if ($mask -band 0x10)   { $rights += 'SERVICE_START' }
    if ($mask -band 0x20)   { $rights += 'SERVICE_STOP' }
    if ($mask -band 0x40)   { $rights += 'SERVICE_PAUSE_CONTINUE' }
    if ($mask -band 0x80)   { $rights += 'SERVICE_INTERROGATE' }
    if ($mask -band 0x100)  { $rights += 'SERVICE_USER_DEFINED_CONTROL' }
    if ($mask -band 0xF01FF){ $rights += 'SERVICE_ALL_ACCESS' }
    return $rights -join ', '
}

function Get-OSBuildInfo {

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue

    $build = 0
    if ($os -and $os.BuildNumber) {
        try { $build = [int]$os.BuildNumber } catch { $build = 0 }
    }

    $ubr = 0
    if ($cv -and $null -ne $cv.UBR) {
        try { $ubr = [int]$cv.UBR } catch { $ubr = 0 }
    }

    $displayVersion = ''
    if ($cv -and $cv.DisplayVersion) { $displayVersion = [string]$cv.DisplayVersion }

    $caption = ''
    if ($os -and $os.Caption) { $caption = [string]$os.Caption }

    return [PSCustomObject]@{
        Caption        = $caption
        Build          = $build
        UBR            = $ubr
        DisplayVersion = $displayVersion
        IsServer       = ($caption -match 'Server')
        IsWin11_25H2   = ($build -eq 26200)
    }
}



function Test-CVE2025_60710 {
    $osInfo = Get-OSBuildInfo

    # Affected: Windows 11 (build 22000+), Server 2022 (20348), Server 2025 (26100)
    $affected = ($osInfo.Build -ge 20348)
    if (-not $affected) {
        Write-Good 'CVE-2025-60710: OS build not in the affected range.' -Category 'CVE-2025-60710'
        return
    }

    # Patched baseline: November 2025 cumulative update.
    # Win 11 25H2 (26200.x) patched at UBR 7171
    # Win 11 24H2 / Server 2025 (26100.x) patched at UBR 7462
    $patchedUBR = if ($osInfo.Build -eq 26200) { 7171 } else { 7462 }

    if ($osInfo.UBR -ge $patchedUBR) {
        Write-Good "CVE-2025-60710: Patched (UBR $($osInfo.UBR) is at least $patchedUBR)." -Category 'CVE-2025-60710'
    } else {
        Write-Bad "CVE-2025-60710: VULNERABLE - UBR $($osInfo.UBR) is below $patchedUBR. Install November 2025 cumulative update." -Category 'CVE-2025-60710'
    }
}

function Test-CVE2026_81963 {
    $osInfo = Get-OSBuildInfo

    $affected = ($osInfo.Build -ge 22000) -or ($osInfo.Caption -match 'Server 2025')
    if (-not $affected) {
        Write-Good 'CVE-2026-81963: OS build not in the affected range.' -Category 'CVE-2026-81963'
        return
    }

    $patchedUBR = 7652   
    if ($osInfo.UBR -ge $patchedUBR) {
        Write-Good "CVE-2026-81963: Patched (UBR $($osInfo.UBR) is at least $patchedUBR)." -Category 'CVE-2026-81963'
    } else {
        Write-Bad "CVE-2026-81963: VULNERABLE - UBR $($osInfo.UBR) is below $patchedUBR. Install September 2026 cumulative update." -Category 'CVE-2026-81963'
    }
}

function Test-ShieldBreakExposure {
    # CVE-2026-69414 / ShieldBreak
    # Prerequisite surface: Defender real-time protection active AND
    # Cloud Files filter driver (cldflt) running.
    $defender   = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $cloudFiles = Get-Service -Name 'cldflt' -ErrorAction SilentlyContinue

    $engineVersion = $null
    if ($defender -and $defender.AMEngineVersion) {
        $engineVersion = [string]$defender.AMEngineVersion
    }

    $fixedEngine = '1.1.26080.3'

    $engineOk = $false
    if ($engineVersion) {
        try { $engineOk = [version]$engineVersion -ge [version]$fixedEngine } catch { $engineOk = $false }
    }

    $surfaceActive = ($defender -and $defender.RealTimeProtectionEnabled -and
                      $cloudFiles -and $cloudFiles.Status -eq 'Running')

    if ($surfaceActive) {
        if ($engineOk) {
            Write-Warn "ShieldBreak surface active (Defender RTP and cldflt). Engine $engineVersion is at least $fixedEngine - base CVE patched, but ShieldCrash bypass exists. Verify latest platform update." -Category 'ShieldBreak'
        } else {
            Write-Bad "ShieldBreak surface active (Defender RTP and cldflt). Engine $engineVersion is below $fixedEngine - VULNERABLE to CVE-2026-69414." -Category 'ShieldBreak'
        }
    } else {
        Write-Good 'ShieldBreak prerequisite surface not active (Defender RTP or cldflt not running).' -Category 'ShieldBreak'
    }
}



function Test-TokenPrivileges {
    Write-SectionHeader 'Token Privileges (SeBackup, SeImpersonate, SeDebug, SeTakeOwnership, SeTcb)'
    try {
        $privOutput = whoami /priv
        $enabled    = $privOutput | Where-Object { $_ -match 'Enabled' } |
                      ForEach-Object { ($_ -split '\s+')[0] }
        $highRisk = @('SeBackupPrivilege','SeImpersonatePrivilege','SeDebugPrivilege',
                      'SeTakeOwnershipPrivilege','SeTcbPrivilege')
        $found = $highRisk | Where-Object { $enabled -contains $_ }
        if ($found) {
            foreach ($p in $found) { Write-Bad "Enabled: $p" -Category 'TokenPrivileges' }
        } else {
            Write-Good 'No high-risk Se* privileges enabled.' -Category 'TokenPrivileges'
        }
    } catch {
        Write-Warn 'Could not enumerate privileges (try running as admin).' -Category 'TokenPrivileges'
    }
}

function Test-AlwaysInstallElevated {
    Write-SectionHeader 'AlwaysInstallElevated'
    $hklm = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
    $hkcu = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue
    if (($hklm.AlwaysInstallElevated -eq 1) -or ($hkcu.AlwaysInstallElevated -eq 1)) {
        Write-Bad 'AlwaysInstallElevated is ENABLED (MSI exploitation).' -Category 'AlwaysInstallElevated'
    } else {
        Write-Good 'AlwaysInstallElevated is DISABLED.' -Category 'AlwaysInstallElevated'
    }
}

function Test-RegistryRunKeys {
    Write-SectionHeader 'Registry Run Keys - Write Access'
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $found = $false
    foreach ($key in $keys) {
        $rel = $key -replace '^HK(LM|CU):\\',''
        if (Test-RegistryKeyWriteable $rel) {
            Write-Bad "Writeable: $key" -Category 'RegistryRunKeys'
            $found = $true
        }
    }
    if (-not $found) { Write-Good 'No writeable Run/RunOnce keys found.' -Category 'RegistryRunKeys' }
}

function Test-StartupFolders {
    Write-SectionHeader 'Startup Folder - Write Access'
    $folders = @(
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp',
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    $found = $false
    foreach ($f in $folders) {
        if ((Test-Path $f) -and (Test-PathWriteable $f)) {
            Write-Bad "Writeable: $f" -Category 'StartupFolders'
            $found = $true
        }
    }
    if (-not $found) { Write-Good 'No writeable Startup folders found.' -Category 'StartupFolders' }
}

function Test-StoredCredentials {
    Write-SectionHeader 'Stored Credentials (cmdkey)'
    $creds = cmdkey /list 2>$null
    if ($creds -match 'Target:' -and $creds -notmatch 'Target: \(null\)') {
        $targets = $creds | Where-Object { $_ -match 'Target:' }
        Write-Bad "Stored credentials detected: $($targets -join ' | ')" -Category 'StoredCredentials'
        Write-Warn "Potential for 'runas /savecred' abuse." -Category 'StoredCredentials'
    } else {
        Write-Good 'No stored credentials found.' -Category 'StoredCredentials'
    }
}

function Test-WeakServiceRegistryPermissions {
    Write-SectionHeader 'Weak Service Registry Permissions'
    $services = Get-CimInstance -ClassName Win32_Service -Property Name, StartMode |
                Where-Object { $_.StartMode -in @('Auto','Manual') }
    $risky = [System.Collections.Generic.List[string]]::new()
    foreach ($svc in $services) {
        $regPath = "SYSTEM\CurrentControlSet\Services\$($svc.Name)"
        if (Test-RegistryKeyWriteable $regPath) {
            $risky.Add($svc.Name)
            if ($risky.Count -ge 10) { break }
        }
    }
    if ($risky.Count -gt 0) {
        Write-Bad "Writeable service registry keys: $($risky -join ', ')" -Category 'WeakServiceRegPerms'
    } else {
        Write-Good 'No obviously weak service registry permissions found.' -Category 'WeakServiceRegPerms'
    }
}

function Test-UnquotedServicePaths {
    Write-SectionHeader 'Unquoted Service Paths (non-Windows services)'
    $unquoted = Get-CimInstance -ClassName Win32_Service -Property Name, PathName |
        Where-Object {
            $_.PathName -like '* *' -and
            $_.PathName -notlike '"*' -and
            $_.PathName -notmatch 'C:\\Windows'
        }
    if ($unquoted) {
        Write-Bad 'Unquoted non-Windows service paths detected:' -Category 'UnquotedServicePaths'
        foreach ($svc in $unquoted | Select-Object -First 5) {
            Write-Warn "  $($svc.Name) -> $($svc.PathName)" -Category 'UnquotedServicePaths'
        }
        if (@($unquoted).Count -gt 5) {
            Write-Warn "  ... and $(@($unquoted).Count - 5) more." -Category 'UnquotedServicePaths'
        }
    } else {
        Write-Good 'No unquoted non-Windows service paths found.' -Category 'UnquotedServicePaths'
    }
}

function Test-WeakServicePermissions {
    Write-SectionHeader 'Weak Service Permissions (SERVICE_CHANGE_CONFIG)'
    $currentSid  = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $everyoneSid = 'S-1-1-0'
    $vuln = [System.Collections.Generic.List[object]]::new()

    $services = Get-CimInstance -ClassName Win32_Service -Property Name, PathName, StartMode

    foreach ($svc in $services) {
        $sddl = & sc.exe sdshow $svc.Name 2>$null
        if ($LASTEXITCODE -ne 0) { continue }
        $aces = ($sddl -replace '^D:','') -split '\)\(' | ForEach-Object { $_.Trim('(',')') }

        foreach ($ace in $aces) {
            if ($ace -notmatch '^A;;') { continue }
            $f = $ace -split ';'
            $permStr = $f[2]; $sid = $f[5]
            $mask = ConvertTo-AccessMask -permStr $permStr

            if (($mask -band 0x2) -eq 0x2 -and ($sid -eq $currentSid -or $sid -eq $everyoneSid)) {
                $vuln.Add([PSCustomObject]@{
                    ServiceName   = $svc.Name
                    BinaryPath    = $svc.PathName
                    StartType     = $svc.StartMode
                    GrantedRights = Get-HumanReadableServiceRights -mask $mask
                    SID           = $sid
                    RawACE        = $ace
                })
                break
            }
        }
    }

    if ($vuln.Count -gt 0) {
        if ($script:UseSpectre) {
            Format-SpectrePanel -Title "[red]15. Weak Service Permissions - $($vuln.Count) service(s) affected[/]" -BorderColor Red -Content {
                Format-SpectreTable -Data $vuln -Columns 'ServiceName','StartType','GrantedRights','SID' -Border Rounded
                Write-SpectreHost "`n[red]RISK:[/] SERVICE_CHANGE_CONFIG allows reconfiguration of the binary path. An attacker can point the service to a malicious executable and restart it for SYSTEM privileges."
            }
        } else {
            Write-Bad "$($vuln.Count) services grant SERVICE_CHANGE_CONFIG to current user or Everyone." -Category 'WeakServicePermissions'
            foreach ($v in $vuln) {
                Write-Host "  Service: $($v.ServiceName)" -ForegroundColor Yellow
                Write-Host "    Binary: $($v.BinaryPath)" -ForegroundColor Gray
                Write-Host "    Rights: $($v.GrantedRights)" -ForegroundColor Gray
                Write-Host "    SID:    $($v.SID)" -ForegroundColor Gray
            }
        }
        Add-Finding -Severity 'Bad' -Category 'WeakServicePermissions' -Message "$($vuln.Count) services with SERVICE_CHANGE_CONFIG to user/Everyone"
    } else {
        Write-Good 'No services grant SERVICE_CHANGE_CONFIG to current user or Everyone.' -Category 'WeakServicePermissions'
    }
}

function Test-ScheduledTaskWritability {
    Write-SectionHeader 'Scheduled Tasks - Writable Action Directories'
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        $found = $false
        foreach ($task in $tasks) {
            $actions = $task.Actions
            if (-not $actions) { continue }
            foreach ($a in $actions) {
                $exe = $a.Execute
                if ($exe -and $exe -match '^[A-Z]:') {
                    $dir = Split-Path $exe -Parent
                    if ($dir -and (Test-Path $dir) -and (Test-PathWriteable $dir)) {
                        Write-Bad "Writeable task action directory: $dir (Task: $($task.TaskName))" -Category 'ScheduledTasks'
                        $found = $true
                    }
                }
            }
        }
        if (-not $found) { Write-Good 'No easily writable scheduled task directories found.' -Category 'ScheduledTasks' }
    } catch {
        Write-Warn 'Could not enumerate scheduled tasks via CIM.' -Category 'ScheduledTasks'
    }
}



function Test-NTLMAuditing {
    Write-SectionHeader 'NTLM Auditing and Restrictions (Server 2025 Baseline)'
    $osInfo = Get-OSBuildInfo
    if (-not $osInfo.IsServer) {
        Write-Warn 'Not Windows Server - NTLM baseline check skipped.' -Category 'NTLM'
        return
    }

    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $restrict = Get-ItemProperty -Path $lsaPath -Name 'RestrictSendingNTLMTraffic' -ErrorAction SilentlyContinue
    if (-not $restrict) {
        Write-Warn 'RestrictSendingNTLMTraffic is NOT configured. Server 2025 baseline recommends restricting NTLM.' -Category 'NTLM'
    } else {
        Write-Good 'NTLM sending restrictions are configured.' -Category 'NTLM'
    }

    $auditIn = Get-ItemProperty -Path "$lsaPath\MSV1_0" -Name 'AuditReceivingNTLMTraffic' -ErrorAction SilentlyContinue
    if ($auditIn) {
        Write-Good 'Incoming NTLM auditing is enabled.' -Category 'NTLM'
    } else {
        Write-Warn 'Incoming NTLM auditing is NOT explicitly enabled. Server 2025 baseline enables this by default - verify GPO.' -Category 'NTLM'
    }
}

function Test-SMBSigning {
    Write-SectionHeader 'SMB Signing (Lateral Movement Risk)'
    $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if (-not $smb) {
        Write-Warn 'Get-SmbServerConfiguration unavailable.' -Category 'SMB'
        return
    }
    if ($smb.RequireSecuritySignature) {
        Write-Good 'SMB signing is REQUIRED.' -Category 'SMB'
    } else {
        Write-Warn 'SMB signing is NOT required. Server 2025 baseline recommends mandatory SMB signing.' -Category 'SMB'
    }
}

function Test-AdministratorProtection {
    Write-SectionHeader 'Administrator Protection (Windows 11 25H2)'
    $osInfo = Get-OSBuildInfo
    if (-not $osInfo.IsWin11_25H2) {
        Write-Warn 'Not Windows 11 25H2 - Administrator Protection check skipped.' -Category 'AdminProtection'
        return
    }
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $val = Get-ItemProperty -Path $regPath -Name 'EnableAdminProtection' -ErrorAction SilentlyContinue
    if ($val -and $val.EnableAdminProtection -eq 1) {
        Write-Warn 'Administrator Protection is ENABLED. Ensure the system is fully patched; bypasses have been demonstrated.' -Category 'AdminProtection'
    } else {
        Write-Good 'Administrator Protection is not enabled (or not configured).' -Category 'AdminProtection'
    }
}



function Test-HiveNightmare {
    Write-SectionHeader 'HiveNightmare (CVE-2021-36934)'
    try {
        $samPath = "$env:windir\system32\config\SAM"
        $file = [System.IO.File]::OpenRead($samPath)
        $file.Close()
        Write-Bad 'SAM file is READABLE by current user (HiveNightmare).' -Category 'HiveNightmare'
    } catch {
        Write-Good 'SAM file is NOT readable (good).' -Category 'HiveNightmare'
    }
}

function Test-KernelBuild {
    Write-SectionHeader 'Kernel Build - Common Exploit Surface'
    $osInfo = Get-OSBuildInfo
    $vulnBuilds = @('14393','17763','19041','19042','19043','20348')
    if ($vulnBuilds -contains [string]$osInfo.Build) {
        Write-Warn "Build $($osInfo.Build) is potentially vulnerable to legacy kernel exploits. Validate patch level manually." -Category 'KernelBuild'
    } else {
        Write-Good "Build $($osInfo.Build) is not in the common legacy vulnerable list." -Category 'KernelBuild'
    }
}

function Test-Spooler {
    Write-SectionHeader 'Print Spooler - SpoolFool / PrintNightmare'
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if (-not ($spooler -and $spooler.Status -eq 'Running')) {
        Write-Good 'Print Spooler is not running.' -Category 'Spooler'
        return
    }

    if (Check-Hotfix 'KB5019964') {
        Write-Good 'KB5019964 installed (SpoolFool mitigated).' -Category 'Spooler'
    } else {
        Write-Warn 'Print Spooler RUNNING and KB5019964 MISSING - potential SpoolFool.' -Category 'Spooler'
    }

    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    $restrict = Get-ItemProperty -Path $regPath -Name 'RestrictDriverInstallationToAdministrators' -ErrorAction SilentlyContinue
    if ($restrict -and $restrict.RestrictDriverInstallationToAdministrators -eq 1) {
        Write-Good 'RestrictDriverInstallationToAdministrators is set (PrintNightmare mitigated).' -Category 'Spooler'
    } else {
        Write-Warn 'Spooler running and RestrictDriverInstallationToAdministrators missing/disabled - check KB5004945 / KB5005010.' -Category 'Spooler'
    }
}



function Show-Summary {
    param([string]$HostName, [string]$User, [bool]$Admin)

    $bad  = @($script:Findings | Where-Object Severity -eq 'Bad').Count
    $warn = @($script:Findings | Where-Object Severity -eq 'Warn').Count

    if ($script:UseSpectre) {
        Format-SpectrePanel -Title '[bold white]AUDIT COMPLETE[/]' -BorderColor White -Content {
            Format-SpectreTable -Data @(
                [PSCustomObject]@{ Metric='Host';             Value=$HostName }
                [PSCustomObject]@{ Metric='User';             Value=$User }
                [PSCustomObject]@{ Metric='Admin';            Value=$Admin }
                [PSCustomObject]@{ Metric='Critical (Bad)';   Value=$bad }
                [PSCustomObject]@{ Metric='Warnings';         Value=$warn }
            ) -Columns 'Metric','Value' -Border Rounded
            Write-SpectreHost "`n[yellow]Review the [red][X][/][yellow] and [yellow][!][/][yellow] items above. Some checks are heuristic - validate manually.[/]"
        }
    } else {
        Write-Host ''
        Write-Host 'AUDIT COMPLETE' -ForegroundColor White
        Write-Host "Critical/Bad: $bad  |  Warnings: $warn" -ForegroundColor Yellow
        Write-Host 'Review the flagged [X] and [!] items above. Some checks are heuristic.' -ForegroundColor Gray
    }
}

function Export-Findings {
    param([string]$Format, [string]$Path)
    if (-not $Path) {
        Write-Warning 'OutputPath is required for Json/Csv export. Skipping export.'
        return
    }
    switch ($Format) {
        'Json' { $script:Findings | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding utf8 }
        'Csv'  { $script:Findings | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8 }
    }
    Write-Host "Findings exported to $Path" -ForegroundColor Gray
}

Clear-Host
$hostName    = $env:COMPUTERNAME
$currentUser = Get-CurrentUser
$isAdmin     = Test-AdminRights

if ($script:UseSpectre) {
    Format-SpectrePanel -Title '[bold white]WINDOWS POTENTIAL ATTACK VECTOR DETECTION - 2026/2027[/]' -BorderColor White -Content {
        Format-SpectreTable -Data @(
            [PSCustomObject]@{ Field='User';   Value=$currentUser }
            [PSCustomObject]@{ Field='Admin';  Value=$isAdmin }
            [PSCustomObject]@{ Field='Host';   Value=$hostName }
            [PSCustomObject]@{ Field='Engine'; Value='PwshSpectreConsole' }
        ) -Columns 'Field','Value' -Border Rounded
        Write-SpectreHost '[gray]developed by d3hack@VulnLab  |  tested on Win 11 25H2 / Server 2025[/]'
    }
} else {
	
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "                                                            " -ForegroundColor White
    Write-Host "        WINDOWS POTENTIAL ATTACK VECTOR DETECTION           " -ForegroundColor White
    Write-Host "                                                            " -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "                               developed by d3hack@VulnLab  " -ForegroundColor White
    Write-Host "                       tested @ Win 11 25H2 ver 26200.9278  " -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "User:  $currentUser" -ForegroundColor Gray
    Write-Host "Admin: $isAdmin" -ForegroundColor Gray
    Write-Host "Host:  $hostName" -ForegroundColor Gray
    Write-Separator
}

Test-TokenPrivileges
Test-AlwaysInstallElevated
Test-HiveNightmare
Test-RegistryRunKeys
Test-StartupFolders
Test-StoredCredentials
Test-WeakServiceRegistryPermissions
Test-UnquotedServicePaths
Test-WeakServicePermissions
Test-ScheduledTaskWritability
Test-KernelBuild
Test-Spooler

Write-Separator
Write-SectionHeader '2026/2027 CVE and Baseline Checks'
Test-CVE2025_60710
Test-CVE2026_81963
Test-ShieldBreakExposure
Test-NTLMAuditing
Test-SMBSigning
Test-AdministratorProtection

Write-Separator
Show-Summary -HostName $hostName -User $currentUser -Admin $isAdmin

if ($OutputFormat -ne 'Console') {
    Export-Findings -Format $OutputFormat -Path $OutputPath
}