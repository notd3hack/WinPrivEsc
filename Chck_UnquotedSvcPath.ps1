<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛          

USAGE: irm <github-raw-link> | iex                
irm is short for Invoke-RestMethod. 
It will download a script from that website. 
iex is short for Invoke-Expression. 
It will run the script

#>
$services = Get-WmiObject -Class Win32_Service

foreach ($service in $services) {
    if ($service.PathName -match '^[^"]* [^"]*') {
        Write-Output "UnquotedSvc: $($service.Name) - $($service.PathName)"
    }
}
