
function Write-Info {
    Write-Host "[*] $($args[0])" -ForegroundColor Cyan
}
function Write-Good {
    Write-Host "[+] $($args[0])" -ForegroundColor Green
}
function Write-Warn {
    Write-Host "[!] $($args[0])" -ForegroundColor Yellow
}
function Write-Bad {
    Write-Host "[X] $($args[0])" -ForegroundColor Red
}
function Write-Separator {
    Write-Host ("-" * 80) -ForegroundColor DarkGray
}

function Get-CurrentUser {
    return ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
}

function Test-AdminRights {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PathWriteable {
    param([string]$Path)
    try {
        $acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue
        if (-not $acl) { return $false }
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        foreach ($rule in $acl.Access) {
            if ($rule.IdentityReference -eq "BUILTIN\Users" -or 
                $rule.IdentityReference -eq "NT AUTHORITY\Authenticated Users" -or
                $rule.IdentityReference -eq $identity.Name) {
                if ($rule.FileSystemRights -match "Write|Modify|FullControl") {
                    if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                        return $true
                    }
                }
            }
        }
        if ($acl.Owner -eq $identity.User -or $acl.Owner -eq "BUILTIN\Users") {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Test-RegistryKeyWriteable {
    param([string]$Path)
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path, $true)
        if ($key -ne $null) { 
            $key.Close()
            return $true 
        }
        return $false
    }
    catch {
        return $false
    }
}

function Check-Hotfix {
    param([string]$KB)
    return (Get-HotFix -Id $KB -ErrorAction SilentlyContinue) -ne $null
}

function Get-DomainDN {
    try {
        $root = [ADSI]"LDAP://RootDSE"
        return $root.defaultNamingContext
    }
    catch { return $null }
}

function Test-DomainGroupMembership {
    param([string]$GroupName)
    $dn = Get-DomainDN
    if (-not $dn) { return $false }
    try {
        $searcher = [ADSISearcher]"(objectClass=group)"
        $searcher.Filter = "(&(objectClass=group)(cn=$GroupName))"
        $result = $searcher.FindOne()
        if ($result -eq $null) { return $false }
        $group = $result.GetDirectoryEntry()
        $members = $group.Invoke("Members") | ForEach-Object { 
            ([ADSI]$_).InvokeGet("samAccountName") 
        }
        $current = (Get-CurrentUser).Split('\')[1]
        return $members -contains $current
    }
    catch { return $false }
}

Clear-Host
Write-Host "============================================================" -ForegroundColor White
Write-Host "    WINDOWS PRIVILEGE ESCALATION SECURITY AUDIT" -ForegroundColor White
Write-Host "    (Checks 21 Common Vectors)" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host "User: $((Get-CurrentUser))" -ForegroundColor Gray
Write-Host "Admin: $(Test-AdminRights)" -ForegroundColor Gray
Write-Host "Host: $env:COMPUTERNAME" -ForegroundColor Gray
Write-Separator

Write-Info "1-5. Checking Token Privileges (SeBackup, SeImpersonate, SeDebug, SeTakeOwnership, SeTcb)"
try {
    $privOutput = whoami /priv
    $enabledPrivs = $privOutput | Where-Object { $_ -match "Enabled" } | ForEach-Object { ($_ -split "\s+")[0] }
    $highRiskPrivs = @("SeBackupPrivilege", "SeImpersonatePrivilege", "SeDebugPrivilege", 
                       "SeTakeOwnershipPrivilege", "SeTcbPrivilege")
    $found = $highRiskPrivs | Where-Object { $enabledPrivs -contains $_ }
    if ($found) {
        foreach ($priv in $found) {
            Write-Bad "  Enabled: $priv"
        }
    } else {
        Write-Good "  No high-risk Se* privileges enabled."
    }
} catch {
    Write-Warn "  Could not enumerate privileges (try running as admin)."
}

Write-Separator
Write-Info "6. Checking AlwaysInstallElevated"
$alwaysHklm = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
$alwaysHkcu = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
if (($alwaysHklm.AlwaysInstallElevated -eq 1) -or ($alwaysHkcu.AlwaysInstallElevated -eq 1)) {
    Write-Bad "  AlwaysInstallElevated is ENABLED (Vulnerable to MSI exploitation)."
} else {
    Write-Good "  AlwaysInstallElevated is DISABLED."
}

Write-Separator
Write-Info "7. Checking DnsAdmins membership (Domain)"
if (Get-DomainDN) {
    if (Test-DomainGroupMembership "DnsAdmins") {
        Write-Bad "  Current user is a MEMBER of DnsAdmins (can load malicious DLLs on DC)."
    } else {
        Write-Good "  Current user is NOT a member of DnsAdmins."
    }
} else {
    Write-Warn "  Not on a domain, skipping."
}

Write-Separator
Write-Info "8. Checking HiveNightmare (CVE-2021-36934)"
try {
    $samPath = "$env:windir\system32\config\SAM"
    $file = [System.IO.File]::OpenRead($samPath)
    $file.Close()
    Write-Bad "  SAM file is READABLE by the current user! (Vulnerable to HiveNightmare)"
} catch {
    Write-Good "  SAM file is NOT readable (good)."
}

Write-Separator
Write-Info "9. Checking Registry Run Keys for write access"
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
$writeableRun = $false
foreach ($key in $runKeys) {
    if (Test-RegistryKeyWriteable $key.Replace("HKLM:\","").Replace("HKCU:\","")) {
        Write-Bad "  Writeable: $key"
        $writeableRun = $true
    }
}
if (-not $writeableRun) {
    Write-Good "  No writeable Run/RunOnce keys found."
}

Write-Separator
Write-Info "10. Checking Startup Folder write access"
$startupFolders = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
$writeableStart = $false
foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        if (Test-PathWriteable $folder) {
            Write-Bad "  Writeable: $folder"
            $writeableStart = $true
        }
    }
}
if (-not $writeableStart) {
    Write-Good "  No writeable Startup folders found."
}

Write-Separator
Write-Info "11. Checking for Stored Credentials (cmdkey)"
$creds = cmdkey /list
if ($creds -match "Target:" -and $creds -notmatch "Target: (null)") {
    Write-Bad "  Stored credentials detected:`n$($creds | Where-Object {$_ -match "Target:"})"
    Write-Warn "  Potential for 'runas /savecred' abuse."
} else {
    Write-Good "  No stored credentials found."
}

Write-Separator
Write-Info "12. Checking for Weak Registry Permissions on Services"
$services = Get-WmiObject -Class Win32_Service | Where-Object { $_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual" }
$riskyRegServices = @()
foreach ($svc in $services) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
    if (Test-RegistryKeyWriteable $regPath.Replace("HKLM:\","")) {
        $riskyRegServices += $svc.Name
    }
    if ($riskyRegServices.Count -ge 10) { break } # Limit output
}
if ($riskyRegServices.Count -gt 0) {
    Write-Bad "  Writeable service registry keys found (examples): $($riskyRegServices -join ', ')"
} else {
    Write-Good "  No obviously weak service registry permissions found."
}

# 13. Unquoted Paths
Write-Separator
Write-Info "13. Checking for Unquoted Service Paths (Windows system services ignored)"
$unquoted = Get-WmiObject -Class Win32_Service | Where-Object {
    $_.PathName -like "* *" -and 
    $_.PathName -notlike '"*' -and 
    $_.PathName -ne $null -and
    $_.PathName -notmatch "C:\\Windows"
}
if ($unquoted) {
    Write-Bad "  Unquoted non-Windows service paths detected (potential binary hijacking):"
    foreach ($svc in $unquoted | Select-Object -First 5) {
        Write-Warn "    $($svc.Name) -> $($svc.PathName)"
    }
    if ($unquoted.Count -gt 5) { Write-Warn "    ... and $($unquoted.Count - 5) more." }
} else {
    Write-Good "  No unquoted non-Windows service paths found."
}

Write-Separator
Write-Info "14. Insecure GUI Applications"
Write-Warn "  Manual check required: Look for 'AlwaysNotify' or 'Interactive Services' running as SYSTEM."

Write-Separator
Write-Info "15. Checking Weak Service Permissions (Authenticated Users Write)"
$weakServices = @()
$svcList = Get-WmiObject -Class Win32_Service | Select-Object -First 30 # Limit to avoid hanging
foreach ($svc in $svcList) {
    try {
        $sd = sc.exe sdshow $svc.Name
        if ($sd -match "A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AU" -or $sd -match "A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BU") {
            $weakServices += $svc.Name
        }
    } catch {}
}
if ($weakServices.Count -gt 0) {
    Write-Bad "  Weak service permissions (modifiable by users): $($weakServices -join ', ')"
} else {
    Write-Good "  No weak service permissions found in the first 30 services."
}

Write-Separator
Write-Info "16. Checking Scheduled Tasks (writable actions)"
try {
    $tasks = schtasks /query /fo list /v
    $foundWriteableTask = $false
    if ($tasks -match "TaskName") {
        # Simple heuristic: check if user can write to task executable paths
        $lines = $tasks -split "`r`n"
        foreach ($line in $lines) {
            if ($line -match "Task To Run:\s+(.+)$") {
                $exe = $matches[1].Trim()
                if ($exe -match "^[A-Z]:") {
                    $dir = Split-Path $exe -Parent
                    if (Test-PathWriteable $dir) {
                        Write-Bad "  Writeable Scheduled Task executable directory: $dir"
                        $foundWriteableTask = $true
                    }
                }
            }
        }
        if (-not $foundWriteableTask) {
            Write-Good "  No easily writable scheduled task directories found."
        }
    }
} catch {
    Write-Warn "  Could not enumerate scheduled tasks."
}

Write-Separator
Write-Info "17. Checking Kernel Build for common exploits"
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$build = $os.BuildNumber
$vulnerableBuilds = @("14393", "17763", "19041", "19042", "19043", "20348")
if ($vulnerableBuilds -contains $build) {
    Write-Warn "  Build $build is potentially vulnerable to kernel exploits (e.g., CVE-2021-1730)."
    Write-Warn "  Check installed patches manually via 'Get-HotFix'."
} else {
    Write-Good "  Build $build is not in the common vulnerable list."
}

# SamAccountName Spoofing (CVE-2021-42278)
Write-Separator
Write-Info "18. Checking SamAccountName Spoofing (CVE-2021-42278/noPac)"
if (Check-Hotfix "KB5008383") {
    Write-Good "  KB5008383 is installed (mitigates noPac)."
} else {
    Write-Warn "  KB5008383 is NOT installed. Domain may be vulnerable to noPac."
}

# SpoolFool (CVE-2022-21999)
Write-Separator
Write-Info "19. Checking SpoolFool (CVE-2022-21999)"
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($spooler -and $spooler.Status -eq "Running") {
    if (Check-Hotfix "KB5019964") {
        Write-Good "  KB5019964 is installed (mitigates SpoolFool)."
    } else {
        Write-Warn "  Print Spooler is RUNNING and KB5019964 is MISSING -> potential SpoolFool."
    }
} else {
    Write-Good "  Print Spooler is not running."
}

# PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
Write-Separator
Write-Info "20. Checking PrintNightmare"
if ($spooler -and $spooler.Status -eq "Running") {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $restrict = Get-ItemProperty -Path $regPath -Name "RestrictDriverInstallationToAdministrators" -ErrorAction SilentlyContinue
    if ($restrict.RestrictDriverInstallationToAdministrators -eq 1) {
        Write-Good "  RestrictDriverInstallationToAdministrators is set (mitigates PrintNightmare)."
    } else {
        Write-Warn "  Spooler is running and RestrictDriverInstallationToAdministrators is missing/disabled!"
        Write-Warn "  Check for KB5004945 or KB5005010."
    }
} else {
    Write-Good "  Spooler is not running."
}

Write-Separator
Write-Info "21. Checking Server Operator Group"
if (Get-DomainDN) {
    if (Test-DomainGroupMembership "Server Operators") {
        Write-Bad "  User is in 'Server Operators' group! (High potential for privilege escalation)."
    } else {
        Write-Good "  User is NOT in 'Server Operators'."
    }
} else {
    $localOps = net localgroup "Server Operators" 2>$null
    if ($localOps -match (Get-CurrentUser).Split('\')[1]) {
        Write-Bad "  User is in local 'Server Operators' group."
    } else {
        Write-Good "  User is NOT in 'Server Operators'."
    }
}

Write-Separator
Write-Host "AUDIT COMPLETE" -ForegroundColor White
Write-Host "Review the flagged [X] and [!] items above. " -ForegroundColor Yellow
Write-Host "Note: Some checks are heuristic; always validate manually." -ForegroundColor Gray
Write-Separator