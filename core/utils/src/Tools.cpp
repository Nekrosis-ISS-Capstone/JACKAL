
#include <utils/headers/tools.h>
#include <functional>
#include <iostream>
#include <tlhelp32.h>
#include "api/headers/api.h"

void Tools::ShowError(const char* error)
{
#ifdef _DEBUG
    MessageBoxA(NULL, error, "Error", MB_ICONERROR | MB_OK);
#endif // DEBUG
}

//void Logging::ShowError(const char* error, int errnum)
//{
//#ifdef _DEBUG
//     Format the error message with the error number
//    std::string errorMessage = std::string(error) + " " + std::to_string(errnum);
//
//     Display the error message using MessageBoxA
//    MessageBoxA(NULL, errorMessage.c_str(), "Error", MB_ICONERROR | MB_OK);
//#endif // DEBUG
//}
//void Logging::DisplayMessage(const char* format, ...)
//{
//#ifdef _DEBUG
//    const int bufferSize = 512;
//    char buffer[bufferSize];
//
//    va_list args;
//    va_start(args, format);
//    vsnprintf(buffer, bufferSize, format, args);
//    va_end(args);
//
//    MessageBoxA(NULL, buffer, "Debug", MB_ICONINFORMATION | MB_OK);
//#endif
//}
//
//
void Tools::PrintConsole(const char *message)
{
	DWORD  dwCharsWritten; // WriteConsole dependency 
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	if (hConsole != INVALID_HANDLE_VALUE) 
	{
		WriteConsoleA(hConsole, message, strlen(message), &dwCharsWritten, NULL);
	}
}


void Tools::ExitProgram(const char* message)
{
    MessageBoxA(NULL, message, "error", MB_ICONWARNING);
    ExitProcess(-1);
}

DWORD Tools::GetPID(const char* process) {

	API::APIResolver& resolver = API::APIResolver::GetInstance();
	API::API_ACCESS api		   = resolver.GetAPIAccess();
	
	DWORD processId = 0;
	HANDLE snapshot = api.func.pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 processEntry;
		processEntry.dwSize = sizeof(PROCESSENTRY32);
		if (api.func.pProcess32First(snapshot, &processEntry)) {
			do {
				if (strcmp(process, processEntry.szExeFile) == 0) {
					processId = processEntry.th32ProcessID;
					break;
				}
			} while (api.func.pProcess32Next(snapshot, &processEntry));
}
		CloseHandle(snapshot);
	}
	return processId;
}

void Tools::EnableDebugConsole() {
//#ifdef _DEBUG
    //if (AllocConsole()) {
    //    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    //    HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);

    //    if (hOut != INVALID_HANDLE_VALUE && hIn != INVALID_HANDLE_VALUE) {
    //        SetConsoleTitle("Debug Console");
    //        SetStdHandle(STD_OUTPUT_HANDLE, hOut);
    //        SetStdHandle(STD_INPUT_HANDLE, hIn);
    //    }
    //}
//#endif


    if (!AllocConsole()) {
        DWORD dw = GetLastError();
        this->ShowError("AllocConsole failed");
        return;
    }

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);

    if (hOut == INVALID_HANDLE_VALUE || hIn == INVALID_HANDLE_VALUE) {
        DWORD dw = GetLastError();
        this->ShowError("GetStdHandle failed");
        return;
    }

    SetConsoleTitle("Debug Console");
    SetStdHandle(STD_OUTPUT_HANDLE, hOut);
    SetStdHandle(STD_INPUT_HANDLE, hIn);
}
