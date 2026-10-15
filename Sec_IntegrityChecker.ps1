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

    .\IntegrityChecker.ps1 -Create
    .\IntegrityChecker.ps1 -IntCheck
    .\IntegrityChecker.ps1 -FileCheck -Path C:\Important
    .\IntegrityChecker.ps1 -Create -Path C:\Important -Force
    .\IntegrityChecker.ps1            # no switches -> falls back to interactive menu
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'Create')]
    [switch]$Create,

    [Parameter(ParameterSetName = 'FileCheck')]
    [switch]$FileCheck,

    [Parameter(ParameterSetName = 'IntCheck')]
    [switch]$IntCheck,

    [Parameter()]
    [string]$Path = (Get-Location).Path,

    [Parameter()]
    [string]$HashFile,

    [Parameter(ParameterSetName = 'Create')]
    [switch]$Force,

    [Parameter()]
    [switch]$Quiet
)


$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    Write-Host "Target path does not exist or is not a folder: $Path" -ForegroundColor Red
    exit 1
}

$Path = (Resolve-Path -LiteralPath $Path).Path

if (-not $HashFile) {
    $HashFile = Join-Path $Path 'SHA256.txt'
}
elseif (-not [System.IO.Path]::IsPathRooted($HashFile)) {
    $HashFile = Join-Path $Path $HashFile
}

function Write-Info {
    param([string]$Message, [string]$Color = 'White')
    if (-not $Quiet) { Write-Host $Message -ForegroundColor $Color }
}

function New-SHA256Manifest {
    [CmdletBinding()]
    param(
        [string]$TargetPath,
        [string]$ManifestPath,
        [switch]$Overwrite
    )

    if ((Test-Path -LiteralPath $ManifestPath) -and -not $Overwrite) {
        $choice = Read-Host "$(Split-Path $ManifestPath -Leaf) already exists. Overwrite? (Y/N)"
        if ($choice -notin @('Y', 'y')) {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            return 1
        }
    }

    try {
        $manifestName = Split-Path $ManifestPath -Leaf
        $files = Get-ChildItem -LiteralPath $TargetPath -File -Recurse |
            Where-Object { $_.FullName -ne $ManifestPath }

        if ($files.Count -eq 0) {
            Write-Host "No files found in '$TargetPath' or its subfolders to hash." -ForegroundColor Yellow
            return 1
        }

        $totalFiles = $files.Count
        $currentFile = 0

        $hashes = foreach ($file in $files) {
            $currentFile++
            $percentComplete = ($currentFile / $totalFiles) * 100

            Write-Progress -Activity "Generating SHA256 hashes" -Status "Processing $($file.FullName)" `
                -PercentComplete $percentComplete `
                -CurrentOperation "File $currentFile of $totalFiles"

            $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName
            $lastModified = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            $relativePath = $file.FullName.Substring($TargetPath.Length).TrimStart('\', '/')

            "$($hash.Hash)|$lastModified|$relativePath"
        }

        Write-Progress -Activity "Generating SHA256 hashes" -Completed

        $hashes | Out-File -FilePath $ManifestPath -Encoding UTF8

        Write-Info "SHA256 manifest generated: $ManifestPath" 'Green'
        Write-Info "Files hashed: $totalFiles (current folder + subfolders)" 'Cyan'
        return 0
    }
    catch {
        Write-Progress -Activity "Generating SHA256 hashes" -Completed
        Write-Host "Error generating SHA256 manifest: $_" -ForegroundColor Red
        return 1
    }
}

function Test-SHA256ManifestExists {
    [CmdletBinding()]
    param(
        [string]$ManifestPath
    )

    if (Test-Path -LiteralPath $ManifestPath) {
        $fileInfo = Get-Item -LiteralPath $ManifestPath
        $lines = Get-Content -LiteralPath $ManifestPath | Where-Object { $_ -match '\S' }
        $fileCount = $lines.Count

        Write-Host "Manifest found: $ManifestPath" -ForegroundColor Green
        Write-Host "Generated on : $($fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
        Write-Host "Entries      : $fileCount" -ForegroundColor Cyan

        $sample = $lines | Select-Object -First 3
        Write-Host "`nSample entries:" -ForegroundColor Cyan
        foreach ($record in $sample) {
            $parts = $record -split '\|', 3
            if ($parts.Count -eq 3) {
                Write-Host "  - $($parts[2])" -ForegroundColor Gray
            }
        }
        if ($fileCount -gt 3) {
            Write-Host "  - ...and $($fileCount - 3) more" -ForegroundColor Gray
        }
        return 0
    }
    else {
        Write-Host "Manifest NOT found: $ManifestPath" -ForegroundColor Yellow
        return 1
    }
}

function Test-FileIntegrity {
    [CmdletBinding()]
    param(
        [string]$TargetPath,
        [string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        Write-Host "Manifest not found: $ManifestPath" -ForegroundColor Red
        Write-Host "Generate it first with -Create." -ForegroundColor Red
        return 1
    }

    try {
        $storedRecords = Get-Content -LiteralPath $ManifestPath | Where-Object { $_ -match '\S' }
        $failedFiles   = @()
        $modifiedFiles = @()
        $passedFiles   = 0
        $missingFiles  = 0

        $totalChecks = $storedRecords.Count
        $currentCheck = 0

        foreach ($record in $storedRecords) {
            $currentCheck++
            $percentComplete = ($currentCheck / $totalChecks) * 100

            Write-Progress -Activity "Verifying file integrity" -Status "Checking files..." `
                -PercentComplete $percentComplete `
                -CurrentOperation "File $currentCheck of $totalChecks"

            $parts = $record -split '\|', 3
            if ($parts.Count -ne 3) {
                Write-Info "Invalid record format: $record" 'Yellow'
                continue
            }

            $storedHash   = $parts[0]
            $storedDate   = $parts[1]
            $relativePath = $parts[2]
            $fullPath     = Join-Path $TargetPath $relativePath

            if (-not (Test-Path -LiteralPath $fullPath)) {
                $status = "$relativePath (File missing) | Originally modified: $storedDate"
                Write-Info "[MISSING] $status" 'Red'
                $failedFiles += $status
                $missingFiles++
                continue
            }

            $currentFileInfo = Get-Item -LiteralPath $fullPath
            $currentHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $fullPath).Hash
            $currentDate = $currentFileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')

            if ($currentHash -eq $storedHash) {
                if ($currentDate -eq $storedDate) {
                    Write-Info "[PASS] $relativePath is healthy" 'Green'
                    $passedFiles++
                }
                else {
                    $status = "$relativePath | Hash valid but modified: $currentDate (was $storedDate)"
                    Write-Info "[MODIFIED] $status" 'Yellow'
                    $modifiedFiles += $status
                }
            }
            else {
                $status = "$relativePath | Hash mismatch | Modified: $currentDate (was $storedDate)"
                Write-Info "[TAMPERED] $status" 'Red'
                $failedFiles += $status
            }
        }

        Write-Progress -Activity "Verifying file integrity" -Completed

        Write-Host "`nIntegrity check completed:" -ForegroundColor Cyan
        Write-Host "Total files checked   : $totalChecks" -ForegroundColor White
        Write-Host "Passed verification   : $passedFiles" -ForegroundColor Green

        if ($modifiedFiles.Count -gt 0) {
            Write-Host "Modified (date changed): $($modifiedFiles.Count)" -ForegroundColor Yellow
            $modifiedFiles | Select-Object -First 5 | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
            if ($modifiedFiles.Count -gt 5) {
                Write-Host "  - ...and $($modifiedFiles.Count - 5) more" -ForegroundColor Yellow
            }
        }

        if ($failedFiles.Count -gt 0) {
            Write-Host "Failed verification    : $($failedFiles.Count - $missingFiles)" -ForegroundColor Red
            Write-Host "Missing files          : $missingFiles" -ForegroundColor Red
            $failedFiles | Select-Object -First 5 | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
            if ($failedFiles.Count -gt 5) {
                Write-Host "  - ...and $($failedFiles.Count - 5) more" -ForegroundColor Red
            }
        }

        if ($passedFiles -eq $totalChecks -and $modifiedFiles.Count -eq 0 -and $failedFiles.Count -eq 0) {
            Write-Host "All files passed integrity check with matching dates!" -ForegroundColor Green
            return 0
        }
        return 2
    }
    catch {
        Write-Progress -Activity "Verifying file integrity" -Completed
        Write-Host "Error during integrity check: $_" -ForegroundColor Red
        return 1
    }
}

function Show-Menu {
    Clear-Host
    Write-Host "=================== Advanced File Integrity Checker ==================="
    Write-Host "                                              -= developed by d3hack =-"
    Write-Host ""
    Write-Host "   1: Generate SHA256.txt file (current folder + subfolders)"
    Write-Host "   2: Check if SHA256.txt file exists"
    Write-Host "   3: Check files integrity against SHA256.txt (with date check)"
    Write-Host "   Q: Quit"
    Write-Host ""
    Write-Host "======================================================================="
    Write-Host "Tip: run with -Create / -FileCheck / -IntCheck for non-interactive use." -ForegroundColor DarkGray
}

function Start-InteractiveMenu {
    do {
        Show-Menu
        $selection = Read-Host "Please make a selection"

        switch ($selection) {
            '1' { New-SHA256Manifest -TargetPath $Path -ManifestPath $HashFile }
            '2' { Test-SHA256ManifestExists -ManifestPath $HashFile }
            '3' { Test-FileIntegrity -TargetPath $Path -ManifestPath $HashFile }
            { $_ -in @('q', 'Q') } { break }
            default { Write-Host "Invalid selection. Please try again." -ForegroundColor Red }
        }

        if ($selection -notin @('q', 'Q')) {
            Pause
        }
    } while ($selection -notin @('q', 'Q'))

    Write-Host "Script ended. Goodbye!"
}


switch ($PSCmdlet.ParameterSetName) {
    'Create' {
        $code = New-SHA256Manifest -TargetPath $Path -ManifestPath $HashFile -Overwrite:$Force
        exit $code
    }
    'FileCheck' {
        $code = Test-SHA256ManifestExists -ManifestPath $HashFile
        exit $code
    }
    'IntCheck' {
        $code = Test-FileIntegrity -TargetPath $Path -ManifestPath $HashFile
        exit $code
    }
    default {
        Start-InteractiveMenu
    }
}
