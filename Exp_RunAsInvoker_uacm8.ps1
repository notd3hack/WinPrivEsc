<#
 ┓      ┓       ┓  ┓   
┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
           ┛          ┛
┳┓┏┓┓┏┏┓┏┓┓┏┓          
┃┃ ┫┣┫┣┫┃ ┃┫           
┻┛┗┛┛┗┛┗┗┛┛┗┛          

 .S       S.    .S_SSSs      sSSs   .S_SsS_S.    .S_SSSs    
.SS       SS.  .SS~SSSSS    d%%SP  .SS~S*S~SS.  .SS~SSSSS   
S%S       S%S  S%S   SSSS  d%S'    S%S `Y' S%S  S%S   SSSS  
S%S       S%S  S%S    S%S  S%S     S%S     S%S  S%S    S%S  
S&S       S&S  S%S SSSS%S  S&S     S%S     S%S  S%S SSSS%P  
S&S       S&S  S&S  SSS%S  S&S     S&S     S&S   &SSSSSSY   
S&S       S&S  S&S    S&S  S&S     S&S     S&S  S&S    S&S  
S&S       S&S  S&S    S&S  S&S     S&S     S&S  S&S    S&S  
S*b       d*S  S*S    S&S  S*b     S*S     S*S  S*S    S&S  
S*S.     .S*S  S*S    S*S  S*S.    S*S     S*S  S*S    S*S  
 SSSbs_sdSSS   S*S    S*S   SSSbs  S*S     S*S   *SSSSSSP   
  YSSP~YSSY    SSS    S*S    YSSP  SSS     S*S    *SSSsY    
                      SP                   SP             
                      Y                    Y               
                                                            
  sSSs    sSSs   .S_sSSs     .S    sSSs    sSSs             
 d%%SP   d%%SP  .SS~YS%%b   .SS   d%%SP   d%%SP             
d%S'    d%S'    S%S   `S%b  S%S  d%S'    d%S'               
S%|     S%S     S%S    S%S  S%S  S%S     S%|                
S&S     S&S     S%S    d*S  S&S  S&S     S&S                
Y&Ss    S&S_Ss  S&S   .S*S  S&S  S&S_Ss  Y&Ss               
`S&&S   S&S~SP  S&S_sdSSS   S&S  S&S~SP  `S&&S              
  `S*S  S&S     S&S~YSY%b   S&S  S&S       `S*S             
   l*S  S*b     S*S   `S%b  S*S  S*b        l*S             
  .S*P  S*S.    S*S    S%S  S*S  S*S.      .S*P             
sSS*S    SSSbs  S*S    S&S  S*S   SSSbs  sSS*S              
YSS'      YSSP  S*S    SSS  S*S    YSSP  YSS'               
                SP          SP                              
                Y           Y   

#>


$exePath = "$env:Temp\yourProgram.exe" # We have to change this before executing powershell command
$key = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
Set-ItemProperty -Path $key -Name $exePath -Value "RunAsInvoker"
Start-Process $exePath
