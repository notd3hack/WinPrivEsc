<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛          

USAGE: irm <github-raw-link> | iex
Enumerate AD Users and Groups
We need change Domain name on every machine or every different corps DC
We need to change OutputPath folder if it needed                
Download Script and User powershell -ep bypass. After that use script with .\Sec_Audit.... 
It will run the script

#>

$domain = New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE")
$defaultNamingContext = $domain.Properties["defaultNamingContext"][0]
$ldapPath = "LDAP://$defaultNamingContext"

$searchRoot = New-Object DirectoryServices.DirectoryEntry($ldapPath)
$searcher = New-Object DirectoryServices.DirectorySearcher($searchRoot)

$searcher.Filter = "(objectClass=user)"
$searcher.PageSize = 1000
$searcher.ReferralChasing = "None"
$searcher.PropertiesToLoad.Add("samaccountname") > $null
$searcher.PropertiesToLoad.Add("description") > $null
$searcher.PropertiesToLoad.Add("memberOf") > $null

$results = $searcher.FindAll()
foreach ($result in $results) {
    $user = $result.Properties
    $username = $user.samaccountname
    $description = $user.description
    $groups = $user.memberof

    if ($groups) {
        $groupNames = $groups | ForEach-Object {
            ($_ -split ',')[0] -replace '^CN=', ''
        }
        $groupList = ($groupNames -join ', ')
    } else {
        $groupList = "No groups"
    }

    Write-Output "$username - $description - Groups: $groupList"
}
