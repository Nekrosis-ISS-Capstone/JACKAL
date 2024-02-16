#pragma once
#include "../headers/AntiAnalysis.h"
//#include "API/headers/custom_ntdll.h"




//#ifndef NT_SUCCESS
//#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
//#endif
//

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
    Logging logging;
    if (Peb(resolver)) {
        logging.ShowError("Debugger Detected! Exiting");
        //this->Nuke(); // TODO: fix function eventually
        exit(60);
    }
    return false;
}

int AntiAnalysis::Nuke(void)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    const wchar_t* NEWSTREAM = L"test";
    size_t RenameSize = sizeof(FILE_RENAME_INFO) + (wcslen(NEWSTREAM) + 1) * sizeof(wchar_t);
    PFILE_RENAME_INFO PFRI = nullptr;
    WCHAR PathSize[MAX_PATH * 2] = { 0 };
    FILE_DISPOSITION_INFO SetDelete = { 0 };
    Logging logging;

    PFRI = (PFILE_RENAME_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RenameSize);

    if (!PFRI)
    {
        logging.ShowError("Error allocating memory");
        return 1;
    }

    ZeroMemory(PathSize, sizeof(PathSize));
    ZeroMemory(&SetDelete, sizeof(FILE_DISPOSITION_INFO));

    SetDelete.DeleteFile = TRUE;

    PFRI->FileNameLength = wcslen(NEWSTREAM) * sizeof(wchar_t);
    wcscpy_s(PFRI->FileName, wcslen(NEWSTREAM) + 1, NEWSTREAM);

    if (GetModuleFileNameW(NULL, PathSize, MAX_PATH * 2) == 0)
    {
        logging.ShowError("Failed to get file name: ", GetLastError());
        HeapFree(GetProcessHeap(), 0, PFRI);
        return 1;
    }

    hFile = CreateFileW(PathSize, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        logging.ShowError("Failed to open the file: ", GetLastError());
        HeapFree(GetProcessHeap(), 0, PFRI);
        return 1;
    }

    logging.EnableDebugConsole();
    printf("hello there");

    if (!SetFileInformationByHandle(hFile, FileRenameInfo, PFRI, RenameSize))
    {
        logging.ShowError("Failed to rewrite file information: ", GetLastError());
        CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, PFRI);
        return 1;
    }

    CloseHandle(hFile);

    hFile = CreateFileW(PathSize, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        logging.ShowError("Failed to open the file again: ", GetLastError());
        HeapFree(GetProcessHeap(), 0, PFRI);
        return 1;
    }

    if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &SetDelete, sizeof(SetDelete)))
    {
        logging.ShowError("Failed to set file disposition: ", GetLastError());
        CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, PFRI);
        return 1;
    }

    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, PFRI);

    return 0;
}
