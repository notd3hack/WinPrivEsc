$files = Get-ChildItem -File
$total = $files.Count
$counter = 0

$hashes = foreach ($file in $files) {
    $counter++
    Write-Progress -Activity "Calculating file hashes..." -Status "Processing $($file.Name)" -PercentComplete (($counter / $total) * 100)

    $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
    [PSCustomObject]@{
        Name = $file.Name
        Size = $file.Length
        Hash = $hash.Hash
    }
}

$duplicates = $hashes | Group-Object Hash, Size | Where-Object { $_.Count -gt 1 }

if ($duplicates.Count -eq 0) {
    Write-Host "No duplicated file found" -ForegroundColor Yellow
} else {
    foreach ($group in $duplicates) {
        $first = $true
        foreach ($dup in $group.Group) {
            if ($first) {
                Write-Host $dup.Name -ForegroundColor Green
                $first = $false
            } else {
                Write-Host $dup.Name -ForegroundColor Red
            }
        }
        Write-Host ""
    }
}
