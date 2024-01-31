#include "../headers/AntiAnalysis.h"
//#include "API/headers/custom_ntdll.h"
#include <winternl.h>



bool AntiAnalysis::Peb(API::APIResolver &resolver)
{
    PROCESS_BASIC_INFORMATION pbi;
    Logging                     tools;

    API::API_ACCESS api = resolver.GetAPIAccess();


    // Replace these functions with API hashed functions
    HANDLE  hProcess = GetCurrentProcess();

    if (api.func.pNtQueryInformationProcess)
    {
        ULONG returnLength;
        NTSTATUS status = api.func.pNtQueryInformationProcess(
            hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            &returnLength
        );

        if (NT_SUCCESS(status))
        {
            if (pbi.PebBaseAddress && pbi.PebBaseAddress->BeingDebugged)
                return true;
        }
        else
        {
            tools.ShowError("Failed with code: ", GetLastError());
            return false;
        }
    }
    else
    {
        tools.ShowError("Failed to get NtQueryInformationProcess address");
    }

    return false;
}

bool AntiAnalysis::PebCheck(API::APIResolver &resolver)
{
    if (Peb(resolver)) {
        MessageBoxA(NULL, "Debugger detected!", "Anti-Debugging", MB_ICONEXCLAMATION);
        // unhook
        exit(60);
    }
    return false;
}
