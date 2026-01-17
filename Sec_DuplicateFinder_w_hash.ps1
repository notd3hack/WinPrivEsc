# Get all files recursively from current directory and subdirectories
$files = Get-ChildItem -File -Recurse
$total = $files.Count
$counter = 0

# Store relative paths for better readability in output
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
}