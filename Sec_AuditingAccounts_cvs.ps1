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
Download Script and User powershell -ep bypass. After that use script with .\Sec_Audit and more 
It will run the script
1. Export all users with key properties
2. Export all groups with their members
3. Create a detailed membership report
#>

$Domain = "VULN.local"
$OutputPath = "$env:USERPROFILE\Desktop\AD_Enumeration_Results"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# 1. 
$Users = Get-ADUser -Filter * -Server $Domain -Properties *
$Users | Select-Object Name, SamAccountName, UserPrincipalName, Enabled, 
    LastLogonDate, PasswordLastSet, PasswordNeverExpires, 
    @{Name="MemberOf";Expression={($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join ";"}} |
    Export-Csv -Path "$OutputPath\Users_$Timestamp.csv" -NoTypeInformation

# 2. 
$Groups = Get-ADGroup -Filter * -Server $Domain -Properties Members
$GroupReport = foreach ($Group in $Groups) {
    $Members = Get-ADGroupMember -Identity $Group -Server $Domain | 
               Select-Object Name, SamAccountName, ObjectClass
    
    [PSCustomObject]@{
        GroupName = $Group.Name
        Description = $Group.Description
        MemberCount = $Members.Count
        UserMembers = ($Members | Where-Object { $_.ObjectClass -eq "user" } | Select-Object -ExpandProperty Name) -join ";"
        ComputerMembers = ($Members | Where-Object { $_.ObjectClass -eq "computer" } | Select-Object -ExpandProperty Name) -join ";"
        GroupMembers = ($Members | Where-Object { $_.ObjectClass -eq "group" } | Select-Object -ExpandProperty Name) -join ";"
    }
}

$GroupReport | Export-Csv -Path "$OutputPath\Groups_$Timestamp.csv" -NoTypeInformation

# 3. 
$DetailedMembership = foreach ($Group in $Groups) {
    $Members = Get-ADGroupMember -Identity $Group -Server $Domain | 
               Select-Object Name, SamAccountName, ObjectClass
    
    foreach ($Member in $Members) {
        [PSCustomObject]@{
            Group = $Group.Name
            MemberName = $Member.Name
            MemberType = $Member.ObjectClass
            SamAccountName = $Member.SamAccountName
        }
    }
}

$DetailedMembership | Export-Csv -Path "$OutputPath\GroupMembership_$Timestamp.csv" -NoTypeInformation

# Display summary report
Write-Host "`n=== Enumeration Complete ===" -ForegroundColor Cyan
Write-Host "Users found: $($Users.Count)" -ForegroundColor Green
Write-Host "Groups found: $($Groups.Count)" -ForegroundColor Green
Write-Host "Reports saved to: $OutputPath" -ForegroundColor Yellow
Write-Host "Filenames:" -ForegroundColor Yellow
Write-Host "- Users_$Timestamp.csv" -ForegroundColor White
Write-Host "- Groups_$Timestamp.csv" -ForegroundColor White
Write-Host "- GroupMembership_$Timestamp.csv" -ForegroundColor White