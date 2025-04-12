Classic DLL Injection:

    OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread



DLL Injection Using SetWindowsHookEx:

    LoadLibrary / LoadLibraryEx, GetProcAdress, SetWindowsHookEx



APC Injection:

    CreateToolhelp32Snapshot, Process32First, Thread32First, Thread32Next, Process32Next, OpenProcess, VirtualAllocEx, WriteProcessMemory, QueueUserAPC / NtQueueApcThread, VirtualFreeEx, CloseHandle



Atom Bombing:

    CreateToolhelp32Snapshot, Thread32First, Thread32Next, OpenThread, CreatEvent, DuplicateHandle, NtQueueApcThread, QueueUserAPC,, GetModuleHandle, GetProcAdress, SetEvent, GetCurrentProcess, SleepEx, WaitForMultipleObjectsEx / MsgWaitForMultipleObjectsEx, CloseHandle



ALPC Injection:

    NtQuerySystemInformation, NtDuplicateObject / ZwDuplicateObject, GetCurrentProcess, NtQueryObject, NtClose, RtlInitUnicodeString, NtConnectPort, VirtualAllocEx, WripteProcessMemory, CompyMemory, ReadProcessMemory, VirtualFreeEx, VirtualQueryEx, GetMappedFileName, OpenProcess, CloseHandle, GetSystemInfo



LockPos:

    CreateFileMappingW, MapViewOfFile, RtlAllocateHeap, NtCreateSecrion, NtMapViewOfSecrion, NtCreateThreadEx



Process Hollowing:

    CreateProcess("CREATE_SUSPENDED"), NtQueryProcessInformation, ReadProcessMemory, GetModuleHandle, GetProcAdress, ZwUnmapViewOfSecrion, NtUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, SetThreadContext, ResumeThread



Process DOPPELGANGING:

    CreateFileTransacted, WriteFile, NtCreateSection, RollbackTrasaction, NtCreateProcessEx, NtResumeThread



Reflective PE Injection:

    CreateFileA, HeapAlloc, OpenProcessToken, OpenProcess, VirtualAlloc, GetProcAdress, LoadRemoteLibrary / LoadLibrary, HeapFree, CloseHandle



Thread Execution Hijacking:

    RtlAdjustPrivilege, OpenProcess, CreateToolhelp32Snapshot, Thread32First, Thread32Next, CloseHandle, VirtualAllocEx, OpenThread, VirtualFree / VirtualFreeEx, SuspendThread, GetThreadContext, VirtualAlloc, WriteProcessMemory, SetThreadContext, ResumeThread



Kernel Callback Table:

    FindWindowA, GetWindowThreadProcessId, OpenProces, NtQueryInformationProcess, ReadProcessMemory, VirtualAllocEx, WriteProcessMemory, SendMessage, VirtualFreeEx



ClibBRTWNDClass:

    FindWindowEx("CLIPBRDWNDCLASS"), OpenProcess, VirtualAllocEx, WriteProcessMemory, SetProp("ClipboardDataObjectInterface"), VirtualFreeEx



Propagate:

    FindWindow("Progman"), FindWindowEx("SHELLDLL_DefView"), GetProp(UxSubclassInfo"), GetWindowThreadProcessId, OpenProcess, ReadProcessMemory, VirtualAllocEx, WriteProcessMemory, SetProp("UxSubclassInfo"), PostMessage, VirtualFreeEx



Early Bird:

    CreateProcessA, VirtualAllocEx, WriteProcessMemory, QueueUserAPC, ResumeThread



Consolewindowclass:

    FindWindow(ConsoleWindowClass"), GetWindowThreadProcessId, OpenProcess, ReadProcessMemory, VirtualAllocEx, WriteProcessMemory, VirtualFreeEx



ToolTip Process Injection:

    FindWindow("tooptips_class32"), OpenProcess, VirtualAllocEx, WriteProcessMemory, VirtualFreeEx, CloseHandle



DNS API:

    GetWindowThreadProcessId, CreateThread, GetTickCount, OpenProcess, VirtualAllocEx, WriteProcessMemory, VirtualFreeEx, TerminateThread