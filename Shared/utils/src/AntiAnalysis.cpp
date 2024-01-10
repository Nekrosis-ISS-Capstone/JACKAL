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
    HMODULE hNtdll   = LoadLibraryW(L"ntdll.dll");

    if (!hNtdll)
    {
        tools.ShowError("Failed to get handle to ntdll");
        return 0;
    }
    
    // Get the process address of NtQueryProcessInformation
   api.func.ptNtQueryInformationProcess = reinterpret_cast<ptNtQueryInformationProcess_t>(
    GetProcAddress(hNtdll, "NtQueryInformationProcess"));


   if (api.func.ptNtQueryInformationProcess)
   {
       tools.ShowError("GetProc address: ", (int)api.func.ptNtQueryInformationProcess);

   }


   // Get the process address of NtQueryProcessInformation
   api.func.ptNtQueryInformationProcess = reinterpret_cast<ptNtQueryInformationProcess_t>(
      API::HdnGetProcAddress(hNtdll, "NtQueryInformationProcess"));


   if (api.func.ptNtQueryInformationProcess)
   {
       tools.ShowError("GetProcessaddress: ", (int)api.func.ptNtQueryInformationProcess);

   }











   // if (api.func.ptNtQueryInformationProcess)
   // {
   //     ULONG returnLength;
   //     NTSTATUS status = api.func.ptNtQueryInformationProcess(
   //         hProcess,
   //         ProcessBasicInformation,
   //         &pbi,
   //         sizeof(pbi),
   //         &returnLength
   //     );

   //     if (NT_SUCCESS(status))
   //     {
   //         PVOID pPebBeingDebugged = (PPEB)__readgsqword(0x60);

   //         if (pPebBeingDebugged)
   //         {
   //             tools.ShowError("Being Debugged");
   //             return true;
   //         }
   //     }
   //     else
   //     {
   //         tools.ShowError("Failed with code: ", GetLastError());
   //         return false;
   //     }
   // }
   // else
   // {
   //     tools.ShowError("Failed to get NtQueryInformationProcess address");
   // }

   // FreeLibrary(hNtdll);
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
