<#
varyoxuna lenet bunu AI yazib, islemese coxda sey elemiyin. Guya Claude bunu duzeldib emelli basdi hala salmali idi amma alinmiyibsa alinmiyib

#>
 
[CmdletBinding()]
param(
    [ValidateSet("Console", "JSON", "CSV", "HTML")]
    [string]$OutputFormat = "Console",
 
    [string]$OutputPath,
 
    [switch]$SkipDomainChecks,
 
    [ValidateSet("All", "Warn", "Bad")]
    [string]$Severity = "All"
)
 
$ErrorActionPreference = "SilentlyContinue"
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
 
# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
 
function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet("Good", "Warn", "Bad", "Info", "Error")][string]$Status,
        [Parameter(Mandatory)][string]$Details,
        [string]$Recommendation = ""
    )
    $Results.Add([PSCustomObject]@{
        Timestamp      = Get-Date -Format o
        Category       = $Category
        Check          = $Check
        Status         = $Status
        Details        = $Details
        Recommendation = $Recommendation
    })
}
 
function Write-Console {
    param([Parameter(Mandatory)]$Finding)
    $color = switch ($Finding.Status) {
        "Good" { "Green" }
        "Warn" { "Yellow" }
        "Bad"  { "Red" }
        "Error" { "Magenta" }
        default { "Cyan" }
    }
    $tag = switch ($Finding.Status) {
        "Good" { "[+]" }; "Warn" { "[!]" }; "Bad" { "[X]" }; "Error" { "[?]" }; default { "[*]" }
    }
    Write-Host "$tag [$($Finding.Category)] $($Finding.Check): $($Finding.Details)" -ForegroundColor $color
}
 
function Test-DirWriteable {
    # Proper ACL-based writable check instead of guessing from a hand-rolled rule list.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    try {
        $testFile = Join-Path $Path ("._writetest_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
        [IO.File]::Create($testFile).Close()
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        return $true
    } catch { return $false }
}
 
function Test-RegKeyWriteable {
    param([Parameter(Mandatory)][string]$Hive, [Parameter(Mandatory)][string]$SubKey)
    try {
        $root = switch ($Hive) {
            "HKLM" { [Microsoft.Win32.Registry]::LocalMachine }
            "HKCU" { [Microsoft.Win32.Registry]::CurrentUser }
        }
        $key = $root.OpenSubKey($SubKey, $true)
        if ($key) { $key.Close(); return $true }
        return $false
    } catch { return $false }
}
 
function Get-ServiceSddlAces {
    # Parses the service's SDDL string using the real .NET SDDL parser
    # (System.Security.AccessControl.RawSecurityDescriptor) - the same
    # mnemonic table Windows itself uses (sc.exe, icacls, etc.), rather than
    # a hand-rolled bitmask parser or a guessed cmdlet parameter.
    # Returns $null with $script:LastSddlError set if parsing failed, so a
    # broken parse can be reported as "Error" rather than silently as "Good".
    param([Parameter(Mandatory)][string]$ServiceName)
    $script:LastSddlError = $null
    $sddlLines = & sc.exe sdshow $ServiceName 2>&1
    $sddl = ($sddlLines -join "").Trim()
    if (-not $sddl -or $sddl -notmatch "D:") {
        $script:LastSddlError = "sc.exe sdshow returned no usable SDDL: $sddl"
        return $null
    }
    try {
        $rsd = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
        return $rsd.DiscretionaryAcl
    } catch {
        $script:LastSddlError = $_.Exception.Message
        return $null
    }
}
 
function Get-CurrentIdentitySids {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sids = @($id.User.Value)
    $sids += ($id.Groups | ForEach-Object { $_.Value })
    return $sids
}
 
function Test-Hotfix {
    param([string]$KB)
    return (Get-HotFix -Id $KB -ErrorAction SilentlyContinue) -ne $null
}
 
function Get-ServiceExecutablePath {
    # Robustly extract the actual binary path from a service's PathName.
    # Handles: a properly quoted path ("C:\a b\c.exe"), an unquoted path with
    # arguments (C:\a\c.exe -k), and - critically - an unquoted path that
    # itself CONTAINS spaces with no arguments (the classic "unquoted service
    # path" vulnerability). A naive split-on-first-space breaks the first and
    # third cases.
    param([Parameter(Mandatory)][string]$PathName)
    if (-not $PathName) { return $null }
    $trimmed = $PathName.Trim()
 
    if ($trimmed.StartsWith('"')) {
        $endQuote = $trimmed.IndexOf('"', 1)
        if ($endQuote -gt 0) { return $trimmed.Substring(1, $endQuote - 1) }
    }
 
    # Try the whole unquoted string as-is first (covers unquoted paths that
    # contain spaces but take no arguments).
    if (Test-Path $trimmed -PathType Leaf -EA SilentlyContinue) { return $trimmed }
 
    # Otherwise progressively shorten at each space boundary until something
    # resolves to a real file (covers "C:\dir\app.exe -arg1 -arg2").
    $parts = $trimmed -split ' '
    for ($i = $parts.Count; $i -ge 1; $i--) {
        $candidate = ($parts[0..($i - 1)] -join ' ')
        if (Test-Path $candidate -PathType Leaf -EA SilentlyContinue) { return $candidate }
    }
    return ($trimmed -split '\s+')[0]
}
 
function Test-FileWriteable {
    # ACL-based check on the FILE itself (not the parent directory) - a
    # directory can deny new-file creation while the file's own DACL still
    # grants Modify/Write/FullControl to the current user or a broad group.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path -PathType Leaf)) { return $false }
    try {
        $acl = Get-Acl -Path $Path -EA Stop
        $sids = Get-CurrentIdentitySids
        $sids += @("S-1-1-0", "S-1-5-11")  # Everyone, Authenticated Users
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -ne "Allow") { continue }
            $ruleSid = $null
            try { $ruleSid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if ($sids -contains $ruleSid -and $rule.FileSystemRights -match "Write|Modify|FullControl") {
                return $true
            }
        }
        return $false
    } catch { return $false }
}
 
function Get-PEImportedDlls {
    # Minimal, dependency-free PE parser: reads a binary's Import Directory
    # Table and returns the DLL names it statically imports. No dumpbin,
    # no objdump, no third-party module - just the documented PE format
    # (DOS header -> e_lfanew -> PE/COFF header -> optional header data
    # directories -> import descriptor array -> RVA-to-file-offset via the
    # section table). This is standard static analysis, the same technique
    # AV/EDR tooling uses to enumerate a binary's dependencies.
    param([Parameter(Mandatory)][string]$Path)
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -lt 0x40 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { return @() } # 'MZ'
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($peOffset -le 0 -or ($peOffset + 24) -ge $bytes.Length) { return @() }
        if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45) { return @() } # 'PE\0\0'
 
        $numSections    = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
        $optHeaderSize  = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
        $optHeaderOffset = $peOffset + 24
        if ($optHeaderSize -eq 0 -or ($optHeaderOffset + 2) -ge $bytes.Length) { return @() }
        $magic = [BitConverter]::ToUInt16($bytes, $optHeaderOffset)
        $isPE32Plus = ($magic -eq 0x20B)
 
        # Data directory #1 (Import Table) offset differs between PE32 and PE32+
        $dataDirOffset = if ($isPE32Plus) { $optHeaderOffset + 112 } else { $optHeaderOffset + 96 }
        if (($dataDirOffset + 8) -ge $bytes.Length) { return @() }
        $importDirRVA = [BitConverter]::ToUInt32($bytes, $dataDirOffset + 8)
        if ($importDirRVA -eq 0) { return @() }
 
        $sectionHeaderOffset = $optHeaderOffset + $optHeaderSize
        $sections = @()
        for ($i = 0; $i -lt $numSections; $i++) {
            $off = $sectionHeaderOffset + ($i * 40)
            if (($off + 24) -ge $bytes.Length) { break }
            $sections += [PSCustomObject]@{
                VA      = [BitConverter]::ToUInt32($bytes, $off + 12)
                VSize   = [BitConverter]::ToUInt32($bytes, $off + 8)
                Raw     = [BitConverter]::ToUInt32($bytes, $off + 20)
                RawSize = [BitConverter]::ToUInt32($bytes, $off + 16)
            }
        }
 
        function Convert-RvaToOffset {
            param([uint32]$Rva)
            foreach ($s in $sections) {
                $span = [Math]::Max($s.VSize, $s.RawSize)
                if ($Rva -ge $s.VA -and $Rva -lt ($s.VA + $span)) { return [int]($s.Raw + ($Rva - $s.VA)) }
            }
            return -1
        }
        function Read-CString {
            param([int]$Offset)
            if ($Offset -lt 0 -or $Offset -ge $bytes.Length) { return $null }
            $sb = [Text.StringBuilder]::new()
            $i = $Offset
            while ($i -lt $bytes.Length -and $bytes[$i] -ne 0) { [void]$sb.Append([char]$bytes[$i]); $i++ }
            return $sb.ToString()
        }
 
        $importOffset = Convert-RvaToOffset -Rva $importDirRVA
        if ($importOffset -lt 0) { return @() }
 
        $dlls = @()
        $entrySize = 20  # sizeof(IMAGE_IMPORT_DESCRIPTOR)
        for ($i = 0; $i -lt 200; $i++) {   # 200 = sanity bound, not a real limit
            $entryOff = $importOffset + ($i * $entrySize)
            if (($entryOff + $entrySize) -gt $bytes.Length) { break }
            $nameRVA = [BitConverter]::ToUInt32($bytes, $entryOff + 12)
            if ($nameRVA -eq 0) { break }  # descriptor array is null-terminated
            $nameOff = Convert-RvaToOffset -Rva $nameRVA
            $name = Read-CString -Offset $nameOff
            if ($name) { $dlls += $name }
        }
        return $dlls | Select-Object -Unique
    } catch { return @() }
}
 
function Find-HijackableImports {
    # For each DLL a binary imports, walks the real Windows DLL search order
    # (app directory -> System32 -> Windows directory -> PATH, assuming the
    # default SafeDllSearchMode) and flags it if: the DLL is missing from
    # every location EXCEPT a writeable one (plant it there), or the
    # directory it actually resolves from is itself writeable (overwrite it
    # in place). This catches the case where folder/file ACL checks on the
    # main EXE come back clean but the binary still pulls in a hijackable
    # dependency.
    param([Parameter(Mandatory)][string]$ExePath)
    $findings = @()
    $dlls = Get-PEImportedDlls -Path $ExePath
    if ($dlls.Count -eq 0) { return $findings }
 
    $appDir = Split-Path $ExePath -Parent
    $searchOrder = @($appDir, "$env:windir\System32", $env:windir) + ($env:Path -split ";" | Where-Object { $_ })
 
    foreach ($dll in $dlls) {
        $resolvedDir = $null
        foreach ($dir in $searchOrder) {
            if (-not $dir) { continue }
            if (Test-Path (Join-Path $dir $dll) -PathType Leaf -EA SilentlyContinue) { $resolvedDir = $dir; break }
        }
        if ($null -eq $resolvedDir) {
            $writeableCandidate = $searchOrder | Where-Object { $_ -and (Test-DirWriteable $_) } | Select-Object -First 1
            if ($writeableCandidate) { $findings += "$dll (not found on disk; resolvable from writeable dir $writeableCandidate)" }
        } elseif (Test-DirWriteable $resolvedDir) {
            $findings += "$dll (loads from writeable dir $resolvedDir)"
        }
    }
    return $findings
}
 
function Get-DomainDN {
    try { return ([ADSI]"LDAP://RootDSE").defaultNamingContext } catch { return $null }
}
 
function Test-DomainGroupMembership {
    param([string]$GroupName)
    $dn = Get-DomainDN
    if (-not $dn) { return $false }
    try {
        $searcher = [ADSISearcher]"(&(objectClass=group)(cn=$GroupName))"
        $result = $searcher.FindOne()
        if (-not $result) { return $false }
        $group = $result.GetDirectoryEntry()
        $members = $group.Invoke("Members") | ForEach-Object { ([ADSI]$_).InvokeGet("samAccountName") }
        $current = (whoami).Split('\')[1]
        return $members -contains $current
    } catch { return $false }
}
 
# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------
 
$currentUser = whoami
$isAdmin = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 
Add-Finding -Category "Context" -Check "CurrentUser" -Status "Info" -Details "$currentUser (Admin: $isAdmin) on $env:COMPUTERNAME"
 
# ---------------------------------------------------------------------------
# 1. Dangerous token privileges
# ---------------------------------------------------------------------------
 
$privOutput = whoami /priv
$enabledPrivs = $privOutput | Where-Object { $_ -match "Enabled" } | ForEach-Object { ($_ -split "\s+")[0] }
$highRiskPrivs = @(
    "SeBackupPrivilege", "SeRestorePrivilege", "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege", "SeDebugPrivilege", "SeTakeOwnershipPrivilege",
    "SeTcbPrivilege", "SeLoadDriverPrivilege", "SeCreateTokenPrivilege", "SeManageVolumePrivilege"
)
$foundPrivs = $highRiskPrivs | Where-Object { $enabledPrivs -contains $_ }
if ($foundPrivs) {
    foreach ($p in $foundPrivs) {
        Add-Finding -Category "TokenPrivileges" -Check $p -Status "Bad" `
            -Details "Enabled for current user" `
            -Recommendation "Review why this token privilege is assigned; it can typically be abused for SYSTEM-level code execution."
    }
} else {
    Add-Finding -Category "TokenPrivileges" -Check "HighRiskPrivileges" -Status "Good" -Details "No high-risk Se* privileges enabled."
}
 
# ---------------------------------------------------------------------------
# 2. AlwaysInstallElevated
# ---------------------------------------------------------------------------
 
$aHklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
$aHkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
if ($aHklm -eq 1 -and $aHkcu -eq 1) {
    Add-Finding -Category "Policy" -Check "AlwaysInstallElevated" -Status "Bad" `
        -Details "Enabled in both HKLM and HKCU" `
        -Recommendation "Any MSI will install with SYSTEM rights. Disable this policy."
} else {
    Add-Finding -Category "Policy" -Check "AlwaysInstallElevated" -Status "Good" -Details "Not fully enabled."
}
 
# ---------------------------------------------------------------------------
# 3. Unattended-install / autologon credential exposure
# ---------------------------------------------------------------------------
 
$credFiles = @(
    "$env:windir\Panther\Unattend.xml",
    "$env:windir\Panther\Unattended.xml",
    "$env:windir\System32\Sysprep\sysprep.xml",
    "$env:windir\System32\Sysprep\Panther\Unattend.xml",
    "C:\Unattend.xml"
)
$foundCredFiles = $credFiles | Where-Object { Test-Path $_ }
if ($foundCredFiles) {
    foreach ($f in $foundCredFiles) {
        Add-Finding -Category "CredentialExposure" -Check "UnattendFile" -Status "Bad" `
            -Details "Readable: $f" -Recommendation "Sysprep/unattend files often contain plaintext or base64 passwords. Delete after provisioning."
    }
} else {
    Add-Finding -Category "CredentialExposure" -Check "UnattendFile" -Status "Good" -Details "No unattended-install files found."
}
 
$autoLogonPwd = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -EA SilentlyContinue).DefaultPassword
if ($autoLogonPwd) {
    Add-Finding -Category "CredentialExposure" -Check "AutoLogonPassword" -Status "Bad" `
        -Details "Plaintext AutoAdminLogon password stored in registry." `
        -Recommendation "Remove DefaultPassword from Winlogon key; use a Credential Guard-compatible approach instead."
} else {
    Add-Finding -Category "CredentialExposure" -Check "AutoLogonPassword" -Status "Good" -Details "No plaintext autologon password found."
}
 
# ---------------------------------------------------------------------------
# 4. HiveNightmare (CVE-2021-36934)
# ---------------------------------------------------------------------------
 
try {
    $fh = [IO.File]::OpenRead("$env:windir\system32\config\SAM")
    $fh.Close()
    Add-Finding -Category "CVE" -Check "HiveNightmare (CVE-2021-36934)" -Status "Bad" `
        -Details "SAM registry hive is readable by the current user." -Recommendation "Patch and restrict ACLs on %windir%\system32\config."
} catch {
    Add-Finding -Category "CVE" -Check "HiveNightmare (CVE-2021-36934)" -Status "Good" -Details "SAM hive not readable."
}
 
# ---------------------------------------------------------------------------
# 5. Writable Run / RunOnce keys
# ---------------------------------------------------------------------------
 
$runKeys = @(
    @{Hive="HKLM"; Sub="SOFTWARE\Microsoft\Windows\CurrentVersion\Run"},
    @{Hive="HKCU"; Sub="SOFTWARE\Microsoft\Windows\CurrentVersion\Run"},
    @{Hive="HKLM"; Sub="SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"},
    @{Hive="HKCU"; Sub="SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"}
)
$writeableRun = $false
foreach ($k in $runKeys) {
    if (Test-RegKeyWriteable -Hive $k.Hive -SubKey $k.Sub) {
        Add-Finding -Category "Persistence" -Check "RunKeyWriteable" -Status "Bad" -Details "$($k.Hive)\$($k.Sub) is writeable."
        $writeableRun = $true
    }
}
if (-not $writeableRun) {
    Add-Finding -Category "Persistence" -Check "RunKeyWriteable" -Status "Good" -Details "No writeable Run/RunOnce keys found."
}
 
# ---------------------------------------------------------------------------
# 6. Writable Startup folders & PATH directories (DLL hijack surface)
# ---------------------------------------------------------------------------
 
$startupFolders = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
$writeableStart = $false
foreach ($folder in $startupFolders) {
    if (Test-DirWriteable $folder) {
        Add-Finding -Category "Persistence" -Check "StartupFolderWriteable" -Status "Bad" -Details $folder
        $writeableStart = $true
    }
}
if (-not $writeableStart) {
    Add-Finding -Category "Persistence" -Check "StartupFolderWriteable" -Status "Good" -Details "No writeable startup folders found."
}
 
$writeablePathDirs = @()
foreach ($dir in ($env:Path -split ";" | Where-Object { $_ })) {
    if (Test-DirWriteable $dir) { $writeablePathDirs += $dir }
}
if ($writeablePathDirs.Count -gt 0) {
    Add-Finding -Category "DLLHijack" -Check "WriteablePathDirectory" -Status "Bad" `
        -Details ("Writeable PATH directories: " + ($writeablePathDirs -join ", ")) `
        -Recommendation "A writeable directory earlier in PATH than a legitimate binary allows DLL/EXE planting."
} else {
    Add-Finding -Category "DLLHijack" -Check "WriteablePathDirectory" -Status "Good" -Details "No writeable PATH directories found."
}
 
# ---------------------------------------------------------------------------
# 7. Stored credentials & PowerShell history scraping
# ---------------------------------------------------------------------------
 
$creds = cmdkey /list
if ($creds -match "Target:" -and $creds -notmatch "Target: \(null\)") {
    Add-Finding -Category "CredentialExposure" -Check "StoredCredentials" -Status "Warn" `
        -Details "cmdkey has stored targets (see 'runas /savecred' abuse)." -Recommendation "Review with 'cmdkey /list'."
} else {
    Add-Finding -Category "CredentialExposure" -Check "StoredCredentials" -Status "Good" -Details "No stored credentials found."
}
 
$histPath = (Get-PSReadlineOption -EA SilentlyContinue).HistorySavePath
if ($histPath -and (Test-Path $histPath)) {
    $hits = Select-String -Path $histPath -Pattern "password|passwd|-AsPlainText|ConvertTo-SecureString" -EA SilentlyContinue
    if ($hits) {
        Add-Finding -Category "CredentialExposure" -Check "PSReadlineHistory" -Status "Warn" `
            -Details "$($hits.Count) line(s) in PowerShell history reference credential material." `
            -Recommendation "Review $histPath manually; do not display raw contents in shared logs."
    } else {
        Add-Finding -Category "CredentialExposure" -Check "PSReadlineHistory" -Status "Good" -Details "No obvious credential strings in PS history."
    }
}
 
# ---------------------------------------------------------------------------
# 8. Weak service permissions (proper SDDL parsing) + binary path writeability
# ---------------------------------------------------------------------------
 
$mySids = Get-CurrentIdentitySids
$everyoneSid = "S-1-1-0"
$authUsersSid = "S-1-5-11"
 
$vulnServices = @()
$unparseableServices = @()
foreach ($svc in (Get-Service | Select-Object -ExpandProperty Name)) {
    $aces = Get-ServiceSddlAces -ServiceName $svc
    if ($null -eq $aces) {
        # Could be "no custom ACL" (inherits defaults - fine) or a genuine
        # parse failure. sc.exe returns empty/garbage for the former, so we
        # only flag it as an error if sdshow actually returned something we
        # couldn't parse.
        if ($script:LastSddlError -and $script:LastSddlError -notmatch "no usable SDDL") {
            $unparseableServices += "$svc ($script:LastSddlError)"
        }
        continue
    }
 
    foreach ($ace in $aces) {
        # AceQualifier, not AceType - AceType on a CommonAce is an enum like
        # "AccessAllowed"/"AccessDenied" too, but AceQualifier is the reliable
        # property exposed by RawSecurityDescriptor's ACE objects.
        if ($ace.AceQualifier -ne "AccessAllowed") { continue }
        $sidStr = $ace.SecurityIdentifier.Value
        if (($mySids -contains $sidStr) -or $sidStr -eq $everyoneSid -or $sidStr -eq $authUsersSid) {
            $rights = $ace.AccessMask
            $canChangeConfig = ($rights -band 0x2) -eq 0x2         # SERVICE_CHANGE_CONFIG
            $isAllAccess     = ($rights -band 0xF01FF) -eq 0xF01FF # SERVICE_ALL_ACCESS
            if ($canChangeConfig -or $isAllAccess) {
                $svcInfo = Get-CimInstance Win32_Service -Filter "Name='$svc'" -EA SilentlyContinue
                $vulnServices += [PSCustomObject]@{
                    Name = $svc; SID = $sidStr; BinaryPath = $svcInfo.PathName; StartMode = $svcInfo.StartMode
                }
            }
        }
    }
}
if ($vulnServices.Count -gt 0) {
    foreach ($v in $vulnServices) {
        Add-Finding -Category "ServiceMisconfig" -Check "SERVICE_CHANGE_CONFIG" -Status "Bad" `
            -Details "Service '$($v.Name)' (StartMode=$($v.StartMode)) grants config-change rights to $($v.SID). BinaryPath: $($v.BinaryPath)" `
            -Recommendation "Reconfiguring this service's ImagePath and restarting it can yield SYSTEM code execution. Tighten the service ACL."
    }
} else {
    Add-Finding -Category "ServiceMisconfig" -Check "SERVICE_CHANGE_CONFIG" -Status "Good" -Details "No services grant config-change rights to current user/Everyone/Authenticated Users."
}
if ($unparseableServices.Count -gt 0) {
    Add-Finding -Category "ServiceMisconfig" -Check "SDDLParseFailure" -Status "Error" `
        -Details ("Could not parse SDDL for: " + ($unparseableServices -join "; ")) `
        -Recommendation "These services were NOT verified - check manually with 'sc.exe sdshow <name>'."
}
 
# Weak registry permissions directly on the service's own key - lets an
# attacker rewrite ImagePath in the registry, bypassing SCM/SDDL entirely.
$weakRegServices = @()
foreach ($svc in (Get-Service | Select-Object -ExpandProperty Name)) {
    if (Test-RegKeyWriteable -Hive "HKLM" -SubKey "SYSTEM\CurrentControlSet\Services\$svc") {
        $weakRegServices += $svc
    }
}
if ($weakRegServices.Count -gt 0) {
    Add-Finding -Category "ServiceMisconfig" -Check "WeakServiceRegistryKey" -Status "Bad" `
        -Details ("Writeable HKLM service registry key(s): " + ($weakRegServices -join ", ")) `
        -Recommendation "Current user can write ImagePath directly in the registry for these services, bypassing service-manager ACLs. Restart/reboot then yields SYSTEM execution."
} else {
    Add-Finding -Category "ServiceMisconfig" -Check "WeakServiceRegistryKey" -Status "Good" -Details "No writeable service registry keys found."
}
 
# Service binary itself writable - directory writability (DLL/EXE planting)
# AND the binary file's own ACL (in-place overwrite), checked separately
# since either alone is exploitable and a directory-only test misses the latter.
$writeableBinaryDirs = @()
$writeableBinaryFiles = @()
foreach ($svc in (Get-CimInstance Win32_Service -EA SilentlyContinue)) {
    if (-not $svc.PathName) { continue }
    $exePath = Get-ServiceExecutablePath -PathName $svc.PathName
    if (-not $exePath -or -not (Test-Path $exePath -PathType Leaf)) { continue }
 
    $dir = Split-Path $exePath -Parent
    if ($dir -and (Test-DirWriteable $dir)) {
        $writeableBinaryDirs += "$($svc.Name) -> $dir"
    }
    if (Test-FileWriteable $exePath) {
        $writeableBinaryFiles += "$($svc.Name) -> $exePath"
    }
}
if ($writeableBinaryDirs.Count -gt 0) {
    Add-Finding -Category "ServiceMisconfig" -Check "WriteableServiceBinaryDir" -Status "Bad" `
        -Details ("Writeable directories hosting service binaries: " + ($writeableBinaryDirs -join "; ")) `
        -Recommendation "A new EXE/DLL can be planted here (search-order hijack) and picked up on service start."
} else {
    Add-Finding -Category "ServiceMisconfig" -Check "WriteableServiceBinaryDir" -Status "Good" -Details "No writeable service-binary directories found."
}
if ($writeableBinaryFiles.Count -gt 0) {
    Add-Finding -Category "ServiceMisconfig" -Check "WeakServiceBinaryFileACL" -Status "Bad" `
        -Details ("Service binaries writeable in place: " + ($writeableBinaryFiles -join "; ")) `
        -Recommendation "The executable's own DACL allows the current user (or Everyone/Authenticated Users) to overwrite it directly, even if the folder is locked down."
} else {
    Add-Finding -Category "ServiceMisconfig" -Check "WeakServiceBinaryFileACL" -Status "Good" -Details "No service binaries with weak file-level ACLs found."
}
 
# DLL search-order hijacking via actual import-table analysis (catches cases
# where the EXE's own directory/file ACL is clean but a dependency it loads
# resolves from - or would be planted into - a writeable directory).
$hijackFindings = @()
foreach ($svc in (Get-CimInstance Win32_Service -EA SilentlyContinue)) {
    if (-not $svc.PathName) { continue }
    $exePath = Get-ServiceExecutablePath -PathName $svc.PathName
    if (-not $exePath -or -not (Test-Path $exePath -PathType Leaf)) { continue }
    foreach ($hit in (Find-HijackableImports -ExePath $exePath)) {
        $hijackFindings += "$($svc.Name): $hit"
    }
}
if ($hijackFindings.Count -gt 0) {
    Add-Finding -Category "ServiceMisconfig" -Check "DLLSearchOrderHijack" -Status "Bad" `
        -Details ($hijackFindings -join "; ") `
        -Recommendation "Plant or overwrite the named DLL in the indicated writeable directory, then restart/trigger the service to get code execution in its context."
} else {
    Add-Finding -Category "ServiceMisconfig" -Check "DLLSearchOrderHijack" -Status "Good" -Details "No hijackable DLL imports found for enumerated service binaries."
}
 
# ---------------------------------------------------------------------------
# 9. Unquoted service paths
# ---------------------------------------------------------------------------
 
$unquoted = Get-CimInstance Win32_Service -EA SilentlyContinue | Where-Object {
    $_.PathName -like "* *" -and $_.PathName -notlike '"*' -and $_.PathName -notmatch "^[A-Za-z]:\\Windows\\"
}
if ($unquoted) {
    foreach ($svc in $unquoted) {
        # Determine which intermediate "C:\Program.exe", "C:\Program Files\Foo.exe",
        # etc. interception points Windows would actually try, and check whether
        # any of the corresponding directories are writeable - that's what turns
        # this from a theoretical finding into a real one.
        $segments = $svc.PathName -split ' '
        $candidateDirs = for ($i = 1; $i -lt $segments.Count; $i++) {
            $partial = ($segments[0..($i - 1)] -join ' ')
            Split-Path $partial -Parent -EA SilentlyContinue
        }
        $writeableCandidate = $candidateDirs | Where-Object { $_ -and (Test-DirWriteable $_) } | Select-Object -First 1
        if ($writeableCandidate) {
            Add-Finding -Category "ServiceMisconfig" -Check "UnquotedServicePath" -Status "Bad" `
                -Details "$($svc.Name) -> $($svc.PathName) (writeable interception point: $writeableCandidate)" `
                -Recommendation "Drop a malicious executable named after the path segment before the space, in the writeable directory, then restart the service."
        } else {
            Add-Finding -Category "ServiceMisconfig" -Check "UnquotedServicePath" -Status "Warn" `
                -Details "$($svc.Name) -> $($svc.PathName) (no writeable interception point found by this scan; verify manually)."
        }
    }
} else {
    Add-Finding -Category "ServiceMisconfig" -Check "UnquotedServicePath" -Status "Good" -Details "No unquoted non-Windows service paths found."
}
 
# ---------------------------------------------------------------------------
# 10. Scheduled tasks with writable target directories
# ---------------------------------------------------------------------------
 
$writeableTasks = @()
try {
    foreach ($task in (Get-ScheduledTask -EA SilentlyContinue)) {
        foreach ($action in $task.Actions) {
            if ($action.Execute -and (Test-Path $action.Execute -PathType Leaf -EA SilentlyContinue)) {
                $dir = Split-Path $action.Execute -Parent
                if ($dir -and (Test-DirWriteable $dir)) {
                    $writeableTasks += "$($task.TaskName) -> $($action.Execute)"
                }
            }
        }
    }
} catch { }
if ($writeableTasks.Count -gt 0) {
    Add-Finding -Category "ScheduledTasks" -Check "WriteableTaskTarget" -Status "Bad" -Details ($writeableTasks -join "; ")
} else {
    Add-Finding -Category "ScheduledTasks" -Check "WriteableTaskTarget" -Status "Good" -Details "No writeable scheduled-task target directories found."
}
 
# ---------------------------------------------------------------------------
# 11. Known CVEs (patch-state heuristics)
# ---------------------------------------------------------------------------
 
$os = Get-CimInstance Win32_OperatingSystem
Add-Finding -Category "Context" -Check "OSBuild" -Status "Info" -Details "Build $($os.BuildNumber), Version $($os.Version)"
 
if (Test-Hotfix "KB5008383") {
    Add-Finding -Category "CVE" -Check "noPac (CVE-2021-42278/42287)" -Status "Good" -Details "KB5008383 installed."
} else {
    Add-Finding -Category "CVE" -Check "noPac (CVE-2021-42278/42287)" -Status "Warn" -Details "KB5008383 not detected; verify domain patch level."
}
 
$spooler = Get-Service -Name Spooler -EA SilentlyContinue
if ($spooler -and $spooler.Status -eq "Running") {
    if (Test-Hotfix "KB5019964") {
        Add-Finding -Category "CVE" -Check "SpoolFool (CVE-2022-21999)" -Status "Good" -Details "KB5019964 installed."
    } else {
        Add-Finding -Category "CVE" -Check "SpoolFool (CVE-2022-21999)" -Status "Warn" -Details "Spooler running, patch not detected."
    }
    $restrict = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name RestrictDriverInstallationToAdministrators -EA SilentlyContinue).RestrictDriverInstallationToAdministrators
    if ($restrict -eq 1) {
        Add-Finding -Category "CVE" -Check "PrintNightmare" -Status "Good" -Details "RestrictDriverInstallationToAdministrators is set."
    } else {
        Add-Finding -Category "CVE" -Check "PrintNightmare" -Status "Warn" -Details "Spooler running without driver-install restriction; verify patch KB5004945+."
    }
} else {
    Add-Finding -Category "CVE" -Check "Spooler-based CVEs" -Status "Good" -Details "Print Spooler is not running."
}
 
# ---------------------------------------------------------------------------
# 12. Sensitive group memberships (local + domain)
# ---------------------------------------------------------------------------
 
$interestingGroups = @("Administrators", "Backup Operators", "Server Operators", "Print Operators", "Account Operators", "DnsAdmins", "Hyper-V Administrators")
$domainDN = if (-not $SkipDomainChecks) { Get-DomainDN } else { $null }
 
foreach ($grp in $interestingGroups) {
    $isMember = $false
    if ($domainDN) {
        $isMember = Test-DomainGroupMembership -GroupName $grp
    } else {
        $local = net localgroup "$grp" 2>$null
        if ($local) { $isMember = $local -match [regex]::Escape((whoami).Split('\')[-1]) }
    }
    if ($isMember) {
        Add-Finding -Category "GroupMembership" -Check $grp -Status "Bad" -Details "Current user is a member of '$grp'."
    }
}
if (-not ($Results | Where-Object { $_.Category -eq "GroupMembership" })) {
    Add-Finding -Category "GroupMembership" -Check "SensitiveGroups" -Status "Good" -Details "No sensitive group memberships detected."
}
 
# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
 
$filtered = switch ($Severity) {
    "Bad"  { $Results | Where-Object { $_.Status -eq "Bad" } }
    "Warn" { $Results | Where-Object { $_.Status -in @("Bad", "Warn") } }
    default { $Results }
}
 
switch ($OutputFormat) {
    "Console" {
        Write-Host "============================================================" -ForegroundColor White
        Write-Host " WINDOWS PRIVILEGE ESCALATION AUDIT" -ForegroundColor White
        Write-Host "============================================================" -ForegroundColor White
        foreach ($f in $filtered) { Write-Console $f }
        Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
        $summary = $Results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
        Write-Host "Summary: $($summary -join ', ')" -ForegroundColor White
    }
    "JSON" {
        if (-not $OutputPath) { throw "OutputPath is required for JSON output." }
        $filtered | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Host "Report written to $OutputPath"
    }
    "CSV" {
        if (-not $OutputPath) { throw "OutputPath is required for CSV output." }
        $filtered | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8
        Write-Host "Report written to $OutputPath"
    }
    "HTML" {
        if (-not $OutputPath) { throw "OutputPath is required for HTML output." }
        $rows = $filtered | ForEach-Object {
            $cls = $_.Status.ToLower()
            "<tr class='$cls'><td>$($_.Category)</td><td>$($_.Check)</td><td>$($_.Status)</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Details))</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Recommendation))</td></tr>"
        }
        $html = @"
<html><head><title>PrivEsc Audit Report</title><style>
body{font-family:Segoe UI,Arial,sans-serif;background:#111;color:#eee;padding:20px}
table{border-collapse:collapse;width:100%} td,th{border:1px solid #444;padding:6px 10px;text-align:left;font-size:14px}
th{background:#222} tr.bad{background:#3a1414} tr.warn{background:#3a3314} tr.good{background:#14301a} tr.info{background:#14202e}
</style></head><body>
<h2>Windows Privilege Escalation Audit — $env:COMPUTERNAME — $(Get-Date)</h2>
<table><tr><th>Category</th><th>Check</th><th>Status</th><th>Details</th><th>Recommendation</th></tr>$($rows -join "")</table>
</body></html>
"@
        $html | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Host "Report written to $OutputPath"
    }
}