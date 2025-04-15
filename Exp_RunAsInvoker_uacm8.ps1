<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛          

                                                    $$$$$$\  
                                                   $$  __$$\ 
$$\   $$\  $$$$$$\   $$$$$$$\        $$$$$$\$$$$\  $$ /  $$ |
$$ |  $$ | \____$$\ $$  _____|       $$  _$$  _$$\  $$$$$$  |
$$ |  $$ | $$$$$$$ |$$ /             $$ / $$ / $$ |$$  __$$< 
$$ |  $$ |$$  __$$ |$$ |             $$ | $$ | $$ |$$ /  $$ |
\$$$$$$  |\$$$$$$$ |\$$$$$$$\        $$ | $$ | $$ |\$$$$$$  |
 \______/  \_______| \_______|$$$$$$\\__| \__| \__| \______/ 
                              \______|                       

#>


$exePath = "$env:Temp\yourProgram.exe" # We have to change this before executing powershell command
$key = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
Set-ItemProperty -Path $key -Name $exePath -Value "RunAsInvoker"
Start-Process $exePath

# not tested