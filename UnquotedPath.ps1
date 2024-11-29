<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛          

USAGE: irm <github-raw-link> | iex                

#>

$services = Get-WmiObject -Class Win32_Service
foreach ($service in $services) {
    # Skip services where the PathName contains "C:\Windows\System32"
    if ($service.PathName -and $service.PathName -notlike "C:\Windows\system32\*") {
        # Check if the path is unquoted and contains spaces
        if ($service.PathName -match '^[^"]* [^"]*') {
            Write-Output "UnquotedSvc: $($service.Name) - $($service.PathName)"
        }
    }
}
