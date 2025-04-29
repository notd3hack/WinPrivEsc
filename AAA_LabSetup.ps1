# VulnCorp AD Lab Setup Script - Simulates OSCP+ AD Vulnerabilities
# Run as Domain Admin on your lab DC

Import-Module ActiveDirectory

# === 1. Create vulnerable users ===
New-ADUser -Name "dev01" -SamAccountName "dev01" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true

New-ADUser -Name "svc-sql" -SamAccountName "svc-sql" -AccountPassword (ConvertTo-SecureString "SQLpass123" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
Set-ADUser -Identity "svc-sql" -ServicePrincipalNames "MSSQLSvc/devmachine.vulncorp.local:1433"

New-ADUser -Name "npreq" -SamAccountName "npreq" -AccountPassword (ConvertTo-SecureString "npreqpass" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "npreq@vulncorp.local" -CannotChangePassword $true -PasswordNotRequired $true
Set-ADUser -Identity "npreq" -Replace @{"DoesNotRequirePreAuth"=$true}

# === 1.1 Create lots of random users for enumeration + fun ===
New-ADOrganizationalUnit -Name "FunUsers" -Path "DC=vulncorp,DC=local" -ErrorAction SilentlyContinue

$names = @(
    "Samir", "Elvin", "Gulnar", "Kamran", "Leyla", "Ali", "Rashad", "Javid", "Farid", "Aysel",
    "Emily", "Oliver", "Sophia", "James", "Isabella", "Ethan", "Mia", "Lucas", "Emma", "Liam"
)

0..19 | ForEach-Object {
    $name = $names[$_]
    $username = "funuser$_"
    New-ADUser -Name $name -SamAccountName $username -AccountPassword (ConvertTo-SecureString "Funpass123!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -Path "OU=FunUsers,DC=vulncorp,DC=local"
}

# === 2. Create a group for abuse (GenericAll) ===
New-ADGroup -Name "AbuseGroup" -GroupScope Global -Path "CN=Users,DC=vulncorp,DC=local"
Add-ADGroupMember -Identity "AbuseGroup" -Members "dev01"
Add-ADPermission -Identity "svc-sql" -User "AbuseGroup" -ExtendedRights "GenericAll"

# === 3. Enable AlwaysInstallElevated on a target machine ===
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1 -Type DWord

# === 4. Install vulnerable service with unquoted path ===
New-Item -Path "C:\Program Files\Vuln App" -ItemType Directory -Force
Set-Content -Path "C:\Program Files\Vuln App\vulnservice.bat" -Value "calc.exe"
sc.exe create VulnService binPath= "C:\Program Files\Vuln App\vulnservice.bat" start= auto

# === 5. Write GPP password to SYSVOL ===
$gppPath = "\\vulncorp.local\SYSVOL\vulncorp.local\Policies\{GPP-Backdoor}\Machine\Preferences\Groups"
New-Item -Path $gppPath -ItemType Directory -Force
$xml = @"
<?xml version='1.0' encoding='utf-8'?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F5FBA-3D8F-4e44-B33C-9DE44C4B9846}" name="gppuser" image="2">
    <Properties action="U" newName="" fullName="GPP User" description="Backdoor account" cpassword="gppEncryptedPasswordHere==" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="gppuser"/>
  </User>
</Groups>
"@
$xml | Set-Content -Path "$gppPath\Groups.xml"

# === 6. Set weak permissions on Startup folder ===
$startupPath = "C:\Users\dev01\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
New-Item -Path $startupPath -ItemType Directory -Force
icacls $startupPath /grant "Everyone:F"

# === 7. Enable SMBv1 and disable signing ===
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force

# === 8. Create a writable NETLOGON folder ===
$netlogonPath = "\\vulncorp.local\NETLOGON"
icacls $netlogonPath /grant "Authenticated Users:(OI)(CI)F"

# === 9. Enable WinRM and RDP access ===
Enable-PSRemoting -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"

Write-Host "[+] VulnCorp AD DC lab vulnerabilities deployed with user hopping, fun accounts, WinRM & RDP enabled."

# === 10. Optional: Create a .bat launcher for this script ===
$batContent = "powershell -ExecutionPolicy Bypass -NoProfile -File \"%~dp0VulnCorp.ps1\""
Set-Content -Path "$PSScriptRoot\LaunchVulnCorpLab.bat" -Value $batContent
Write-Host "[+] Batch launcher created as LaunchVulnCorpLab.bat in script directory."
