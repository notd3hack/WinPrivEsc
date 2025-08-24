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
Before the Execution: 
1. Firstly Change Domain name from VULN.local because its for testing purpouse only and tested on local lab
2. Export all users
3. Export all groups with members
4. Generate summary report 
#>

$Domain = "VULN.local"
$OutputPath = "$env:USERPROFILE\Desktop\AD_Enum_Reports"

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# 1. 
Get-ADUser -Filter * -Server $Domain -Properties * | 
    Export-Csv -Path "$OutputPath\01_All_Users.csv" -NoTypeInformation

# 2. 
Get-ADGroup -Filter * -Server $Domain -Properties * | 
    Select-Object Name, Description, @{Name="Members";Expression={$_.Members -join ";"}} | 
    Export-Csv -Path "$OutputPath\02_All_Groups.csv" -NoTypeInformation

# 3. 
$Report = @()
Get-ADGroup -Filter * -Server $Domain | ForEach-Object {
    $Members = Get-ADGroupMember -Identity $_ -Server $Domain | 
               Select-Object -ExpandProperty Name
    $Report += [PSCustomObject]@{
        Group = $_.Name
        MemberCount = $Members.Count
        Members = $Members -join ", "
    }
}

$Report | Export-Csv -Path "$OutputPath\03_Group_Membership_Summary.csv" -NoTypeInformation

Write-Host "`nEnumeration complete! Reports saved to $OutputPath" -ForegroundColor Green
dir $OutputPath