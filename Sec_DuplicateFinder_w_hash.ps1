<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛  

Designed for using agains self forking program component to freeup some spaces.
Be super carefull while using it. This script can scan current folder "files, folders, subfolders"
Before using this script start powershell with "powershell -ep bypass"

#>


$files = Get-ChildItem -File -Recurse
$total = $files.Count
$counter = 0

$relativePath = Get-Location

$hashes = foreach ($file in $files) {
    $counter++
    $relativeFilePath = $file.FullName.Substring($relativePath.Path.Length + 1)
    Write-Progress -Activity "Calculating file hashes..." -Status "Processing $relativeFilePath" -PercentComplete (($counter / $total) * 100)

    $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
    [PSCustomObject]@{
        Name = $file.Name
        FullPath = $file.FullName
        RelativePath = $relativeFilePath
        Size = $file.Length
        Hash = $hash.Hash
    }
}

Write-Progress -Activity "Calculating file hashes..." -Completed

$duplicates = $hashes | Group-Object Hash, Size | Where-Object { $_.Count -gt 1 }

if ($duplicates.Count -eq 0) {
    Write-Host "No duplicated files found" -ForegroundColor Yellow
} else {
    Write-Host "`nFound $($duplicates.Count) groups of duplicate files:`n" -ForegroundColor Cyan
    
    foreach ($group in $duplicates) {
        Write-Host "Duplicate Group (Hash: $($group.Name.Split(',')[0]), Size: $($group.Name.Split(',')[1]))" -ForegroundColor Magenta
        Write-Host "=" * 80
        
        $first = $true
        foreach ($dup in $group.Group) {
            if ($first) {
                Write-Host "[ORIGINAL] $($dup.RelativePath)" -ForegroundColor Green
                $first = $false
            } else {
                Write-Host "[DUPLICATE] $($dup.RelativePath)" -ForegroundColor Red
            }
        }
        Write-Host "`n"
    }
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    $deleteChoice = Read-Host "Do you want to delete duplicate files? (Y/N)"
    
    if ($deleteChoice -eq "Y" -or $deleteChoice -eq "y") {
        $deletedCount = 0
        $totalSpaceSaved = 0
        
        foreach ($group in $duplicates) {
            $first = $true
            foreach ($dup in $group.Group) {
                if (-not $first) {
                    try {
                        Remove-Item -Path $dup.FullPath -Force -ErrorAction Stop
                        Write-Host "Deleted: $($dup.RelativePath)" -ForegroundColor Yellow
                        $deletedCount++
                        $totalSpaceSaved += $dup.Size
                    } catch {
                        Write-Host "Error deleting $($dup.RelativePath): $_" -ForegroundColor Red
                    }
                }
                $first = $false
            }
        }
        
        $spaceSavedMB = [math]::Round($totalSpaceSaved / 1MB, 2)
        $spaceSavedGB = [math]::Round($totalSpaceSaved / 1GB, 2)
        
        Write-Host "`n" + ("=" * 60) -ForegroundColor Green
        Write-Host "SUMMARY:" -ForegroundColor Green
        Write-Host "Deleted $deletedCount duplicate files" -ForegroundColor Green
        Write-Host "Space saved: $spaceSavedMB MB ($spaceSavedGB GB)" -ForegroundColor Green
        Write-Host "=" * 60 -ForegroundColor Green
    } else {
        Write-Host "No files were deleted." -ForegroundColor Yellow
    }
}