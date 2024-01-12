#include "../headers/AntiAnalysis.h"
#include <winternl.h>
//#include "API/headers/ntdll.h"

//
//AntiAnalysis::AntiAnalysis()
//{
//
////LoadLibrary("");
//}


bool AntiAnalysis::Peb()
{
    API::API_ACCESS           api;
    PROCESS_BASIC_INFORMATION pbi;
    Tools                     tools;

    // Replace these functions with API hashed functions
    HANDLE  hProcess = GetCurrentProcess();

    if (api.func.ptNtQueryInformationProcess)
    {
        ULONG returnLength;
        NTSTATUS status = api.func.ptNtQueryInformationProcess(
            hProcess,
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            &returnLength
        );

        if (NT_SUCCESS(status))
        {
            if (pbi.PebBaseAddress && pbi.PebBaseAddress->BeingDebugged)
            {
                return true;
            }
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

bool AntiAnalysis::PebCheck(/*DWORD64& nStartTime*/)
{
    if (Peb()) {
        MessageBoxA(NULL, "Debugger detected!", "Anti-Debugging", MB_ICONEXCLAMATION);
        // unhook
        exit(60);
    }
    return false;
}
