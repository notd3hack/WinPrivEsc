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
    # Check for unquoted paths and ignore paths containing "C:\Windows\System32\svchost.exe"
    if ($service.PathName -match '^[^"]* [^"]*' -and $service.PathName -notlike "C:\Windows\System32\svchost.exe*") {
        Write-Output "Unquoted service path found: $($service.Name) - $($service.PathName)"
    }
}
