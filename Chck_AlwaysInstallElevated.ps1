$hkcu = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
$hklm = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue

if (($hkcu.AlwaysInstallElevated -eq 1) -and ($hklm.AlwaysInstallElevated -eq 1)) {
    Write-Host "[!] AlwaysInstallElevated is ENABLED. This is a security risk!" -ForegroundColor Red
} elseif (($hkcu.AlwaysInstallElevated -eq 1) -or ($hklm.AlwaysInstallElevated -eq 1)) {
    Write-Host "[*] One registry key is set, but not both. Not exploitable yet." -ForegroundColor Yellow
} else {
    Write-Host "[+] AlwaysInstallElevated is DISABLED. No risk found." -ForegroundColor Green
}
