$services = Get-WmiObject -Class Win32_Service

foreach ($service in $services) {
    if ($service.PathName -match '^[^"]* [^"]*') {
        Write-Output "Unquoted service path found: $($service.Name) - $($service.PathName)"
    }
}
