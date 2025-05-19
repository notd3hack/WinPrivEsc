<#
.SYNOPSIS
    Advanced File Integrity Checker with Modification Date Tracking
.DESCRIPTION
    This script provides options to generate SHA256 hashes for files in the current directory,
    check for the existence of a SHA256.txt file, and verify file integrity against stored hashes.
.NOTES
    File Name      : Sec_IntegrityChecker.ps1
    Author         : Abbas "d3hack" Aghayev
    Prerequisite   : PowerShell 5.1 or later
#>

function Show-Menu {
    Clear-Host
    Write-Host "=================== Advanced File Integrity Checker ==================="
    Write-Host "1: Generate SHA256.txt file for all files in current directory"
    Write-Host "2: Check if SHA256.txt file exists"
    Write-Host "3: Check files integrity against SHA256.txt (with date check)"
    Write-Host "Q: Quit"
    Write-Host "======================================================================="
}

function Generate-SHA256File {
    $sha256File = "SHA256.txt"
    
    if (Test-Path $sha256File) {
        $choice = Read-Host "SHA256.txt already exists. Overwrite? (Y/N)"
        if ($choice -ne "Y" -and $choice -ne "y") {
            Write-Host "Operation cancelled."
            return
        }
    }
    
    try {
        # Get all files in current directory except SHA256.txt itself
        $files = Get-ChildItem -File | Where-Object { $_.Name -ne $sha256File }
        
        if ($files.Count -eq 0) {
            Write-Host "No files found in the current directory to hash."
            return
        }
        
        # Initialize progress bar variables
        $currentFile = 1
        $totalFiles = $files.Count
        
        # Create or overwrite SHA256.txt
        $hashes = foreach ($file in $files) {
            # Calculate progress percentage
            $percentComplete = ($currentFile / $totalFiles) * 100
            
            # Show progress bar
            Write-Progress -Activity "Generating SHA256 hashes" -Status "Processing $($file.Name)" `
                -PercentComplete $percentComplete `
                -CurrentOperation "File $currentFile of $totalFiles"
            
            # Calculate hash and get last write time
            $hash = Get-FileHash -Algorithm SHA256 -Path $file.FullName
            $lastModified = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            
            # Format: HASH|MODIFIED_DATE|FILENAME
            "$($hash.Hash)|$lastModified|$($file.Name)"
            
            $currentFile++
        }
        
        # Complete the progress bar
        Write-Progress -Activity "Generating SHA256 hashes" -Completed
        
        $hashes | Out-File -FilePath $sha256File -Encoding UTF8
        Write-Host "SHA256.txt has been generated successfully with $($files.Count) file hashes and timestamps." -ForegroundColor Green
    }
    catch {
        Write-Progress -Activity "Generating SHA256 hashes" -Completed
        Write-Host "Error generating SHA256 file: $_" -ForegroundColor Red
    }
}

function Check-SHA256FileExists {
    $sha256File = "SHA256.txt"
    
    if (Test-Path $sha256File) {
        $fileInfo = Get-Item $sha256File
        $fileCount = (Get-Content $sha256File).Count
        Write-Host "SHA256.txt file exists in the current directory." -ForegroundColor Green
        Write-Host "Generated on: $($fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"))" -ForegroundColor Cyan
        Write-Host "Contains hashes for $fileCount files" -ForegroundColor Cyan
    }
    else {
        Write-Host "SHA256.txt file does NOT exist in the current directory." -ForegroundColor Yellow
    }
}

function Check-FileIntegrity {
    $sha256File = "SHA256.txt"
    
    if (-not (Test-Path $sha256File)) {
        Write-Host "SHA256.txt not found. Please generate it first (Option 1)." -ForegroundColor Red
        return
    }
    
    try {
        $storedRecords = Get-Content $sha256File | Where-Object { $_ -match "\S" }
        $failedFiles = @()
        $passedFiles = 0
        $modifiedFiles = @()
        
        # Initialize progress bar variables
        $currentCheck = 1
        $totalChecks = $storedRecords.Count
        
        foreach ($record in $storedRecords) {
            # Calculate progress percentage
            $percentComplete = ($currentCheck / $totalChecks) * 100
            
            # Show progress bar
            Write-Progress -Activity "Verifying file integrity" -Status "Checking files..." `
                -PercentComplete $percentComplete `
                -CurrentOperation "File $currentCheck of $totalChecks"
            
            # Split the record into parts (HASH|DATE|FILENAME)
            $parts = $record -split "\|", 3
            if ($parts.Count -ne 3) {
                Write-Host "Invalid record format in SHA256.txt: $record" -ForegroundColor Yellow
                $currentCheck++
                continue
            }
            
            $storedHash = $parts[0]
            $storedDate = $parts[1]
            $fileName = $parts[2]
            
            if (-not (Test-Path $fileName)) {
                $status = "$fileName (File missing) | Originally modified: $storedDate"
                Write-Host "[MISSING] $status" -ForegroundColor Red
                $failedFiles += $status
                $currentCheck++
                continue
            }
            
            $currentFile = Get-Item $fileName
            $currentHash = (Get-FileHash -Algorithm SHA256 -Path $fileName).Hash
            $currentDate = $currentFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            
            # Check both hash and modification date
            if ($currentHash -eq $storedHash) {
                if ($currentDate -eq $storedDate) {
                    Write-Host "[PASS] $fileName file is healthy" -ForegroundColor Green
                    $passedFiles++
                }
                else {
                    $status = "$fileName | Hash valid but modified: $currentDate (was $storedDate)"
                    Write-Host "[MODIFIED] $status" -ForegroundColor Yellow
                    $modifiedFiles += $status
                }
            }
            else {
                $status = "$fileName | Hash mismatch | Modified: $currentDate (was $storedDate)"
                Write-Host "[TAMPERED] $status" -ForegroundColor Red
                $failedFiles += $status
            }
            
            $currentCheck++
        }
        
        # Complete the progress bar
        Write-Progress -Activity "Verifying file integrity" -Completed
        
        Write-Host "`nIntegrity check completed:" -ForegroundColor Cyan
        Write-Host "Passed: $passedFiles" -ForegroundColor Green
        if ($modifiedFiles.Count -gt 0) {
            Write-Host "Modified (hash valid but date changed): $($modifiedFiles.Count)" -ForegroundColor Yellow
            Write-Host "Modified files:"
            $modifiedFiles | ForEach-Object { Write-Host "- $_" -ForegroundColor Yellow }
        }
        if ($failedFiles.Count -gt 0) {
            Write-Host "Failed/Tampered: $($failedFiles.Count)" -ForegroundColor Red
            Write-Host "Failed files:"
            $failedFiles | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
        }
        if ($passedFiles -eq $totalChecks -and $modifiedFiles.Count -eq 0 -and $failedFiles.Count -eq 0) {
            Write-Host "All files passed integrity check with matching dates!" -ForegroundColor Green
        }
    }
    catch {
        Write-Progress -Activity "Verifying file integrity" -Completed
        Write-Host "Error during integrity check: $_" -ForegroundColor Red
    }
}

# Main script execution
do {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    
    switch ($selection) {
        '1' { Generate-SHA256File }
        '2' { Check-SHA256FileExists }
        '3' { Check-FileIntegrity }
        'q' { break }
        'Q' { break }
        default { Write-Host "Invalid selection. Please try again." -ForegroundColor Red }
    }
    
    if ($selection -ne 'q' -and $selection -ne 'Q') {
        Pause
    }
} while ($selection -ne 'q' -and $selection -ne 'Q')

Write-Host "Script ended. Goodbye!"