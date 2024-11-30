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
    if ($service.PathName -notlike 'C:\Windows\System32*') {
        if ($service.PathName -match '^[^"]* [^"]*') {
            Write-Output "UnquotedSvc: $($service.Name) - $($service.PathName)"
        }
    }
}
