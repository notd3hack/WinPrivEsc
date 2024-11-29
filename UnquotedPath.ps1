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
    if ($service.PathName -match '^[^"]* [^"]*') {
        if ($service.PathName -and $service.PathName -notlike "C:\Windows\system32\svchost.exe") {
            Write-Output "UnquotedSvc: $($service.Name) - $($service.PathName)"
        }
    }
}
