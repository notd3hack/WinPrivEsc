<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛  

Advanced File Integrity Checker and Modification Tracker with Subfolder Support
This script provides options to generate SHA256 hashes for files in current directory
and all subfolders, check for SHA256.txt, and verify file integrity against stored hashes.

#>

function Show-Menu {
    Clear-Host
    Write-Host "=================== Advanced File Integrity Checker ==================="
    Write-Host "                                              -= developed by d3hack =-"
    Write-Host "                                                                       "
    Write-Host "   1: Generate SHA256.txt file (current folder + subfolders)"
    Write-Host "   2: Check if SHA256.txt file exists"
    Write-Host "   3: Check files integrity against SHA256.txt (with date check)"
    Write-Host "   Q: Quit"
    Write-Host "                                                                       "
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
        $files = Get-ChildItem -File -Recurse | Where-Object { $_.Name -ne $sha256File }
        
        if ($files.Count -eq 0) {
            Write-Host "No files found in the current directory or subfolders to hash."
            return
        }
        
        $currentFile = 1
        $totalFiles = $files.Count
        
        $hashes = foreach ($file in $files) {
            $percentComplete = ($currentFile / $totalFiles) * 100
            
            Write-Progress -Activity "Generating SHA256 hashes" -Status "Processing $($file.FullName)" `
                -PercentComplete $percentComplete `
                -CurrentOperation "File $currentFile of $totalFiles"
            
            $hash = Get-FileHash -Algorithm SHA256 -Path $file.FullName
            $lastModified = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            
            $relativePath = $file.FullName.Substring((Get-Location).Path.Length + 1)
            
            "$($hash.Hash)|$lastModified|$relativePath"
            
            $currentFile++
        }
        
        Write-Progress -Activity "Generating SHA256 hashes" -Completed
        
        $hashes | Out-File -FilePath $sha256File -Encoding UTF8
        Write-Host "SHA256.txt has been generated successfully with $($files.Count) file hashes and timestamps." -ForegroundColor Green
        Write-Host "Includes files from current folder and all subfolders." -ForegroundColor Cyan
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
        Write-Host "Generated on: $($fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
        Write-Host "Contains hashes for $fileCount files" -ForegroundColor Cyan
        
        $sampleRecords = Get-Content $sha256File | Select-Object -First 3
        Write-Host "`nSample records:" -ForegroundColor Cyan
        $sampleRecords | ForEach-Object {
            $parts = $_ -split "\|", 3
            if ($parts.Count -eq 3) {
                Write-Host "- $($parts[2])" -ForegroundColor Gray
            }
        }
        if ($fileCount -gt 3) {
            Write-Host "- ...and $($fileCount - 3) more" -ForegroundColor Gray
        }
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
        $missingFiles = 0
        
        $currentCheck = 1
        $totalChecks = $storedRecords.Count
        
        foreach ($record in $storedRecords) {
            $percentComplete = ($currentCheck / $totalChecks) * 100
            
            Write-Progress -Activity "Verifying file integrity" -Status "Checking files..." `
                -PercentComplete $percentComplete `
                -CurrentOperation "File $currentCheck of $totalChecks"
            
            $parts = $record -split "\|", 3
            if ($parts.Count -ne 3) {
                Write-Host "Invalid record format in SHA256.txt: $record" -ForegroundColor Yellow
                $currentCheck++
                continue
            }
            
            $storedHash = $parts[0]
            $storedDate = $parts[1]
            $relativePath = $parts[2]
            $fullPath = Join-Path (Get-Location) $relativePath
            
            if (-not (Test-Path $fullPath)) {
                $status = "$relativePath (File missing) | Originally modified: $storedDate"
                Write-Host "[MISSING] $status" -ForegroundColor Red
                $failedFiles += $status
                $missingFiles++
                $currentCheck++
                continue
            }
            
            $currentFile = Get-Item $fullPath
            $currentHash = (Get-FileHash -Algorithm SHA256 -Path $fullPath).Hash
            $currentDate = $currentFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            
            if ($currentHash -eq $storedHash) {
                if ($currentDate -eq $storedDate) {
                    Write-Host "[PASS] $relativePath file is healthy" -ForegroundColor Green
                    $passedFiles++
                }
                else {
                    $status = "$relativePath | Hash valid but modified: $currentDate (was $storedDate)"
                    Write-Host "[MODIFIED] $status" -ForegroundColor Yellow
                    $modifiedFiles += $status
                }
            }
            else {
                $status = "$relativePath | Hash mismatch | Modified: $currentDate (was $storedDate)"
                Write-Host "[TAMPERED] $status" -ForegroundColor Red
                $failedFiles += $status
            }
            
            $currentCheck++
        }
        
        Write-Progress -Activity "Verifying file integrity" -Completed
        
        Write-Host "`nIntegrity check completed:" -ForegroundColor Cyan
        Write-Host "Total files checked: $totalChecks" -ForegroundColor White
        Write-Host "Passed verification: $passedFiles" -ForegroundColor Green
        if ($modifiedFiles.Count -gt 0) {
            Write-Host "Modified (hash valid but date changed): $($modifiedFiles.Count)" -ForegroundColor Yellow
            Write-Host "Modified files:"
            $modifiedFiles | Select-Object -First 5 | ForEach-Object { Write-Host "- $_" -ForegroundColor Yellow }
            if ($modifiedFiles.Count -gt 5) {
                Write-Host "- ...and $($modifiedFiles.Count - 5) more" -ForegroundColor Yellow
            }
        }
        if ($failedFiles.Count -gt 0) {
            Write-Host "Failed verification: $($failedFiles.Count - $missingFiles)" -ForegroundColor Red
            Write-Host "Missing files: $missingFiles" -ForegroundColor Red
            Write-Host "Problem files:"
            $failedFiles | Select-Object -First 5 | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
            if ($failedFiles.Count -gt 5) {
                Write-Host "- ...and $($failedFiles.Count - 5) more" -ForegroundColor Red
            }
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