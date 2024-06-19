#include <utils/headers/tools.h>
#include <functional>
#include <iostream>
#include <tlhelp32.h>

void Tools::ShowError(const char* error)
{
//#ifdef _DEBUG
    MessageBoxA(NULL, error, "Error", MB_ICONERROR | MB_OK);
//#endif // DEBUG
}

void Tools::PrintConsole(const char *message)
{
	DWORD  dwCharsWritten; // WriteConsole dependency 
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	if (hConsole != INVALID_HANDLE_VALUE) 
		WriteConsoleA(hConsole, message, strlen(message), &dwCharsWritten, NULL);
}

void Tools::PrintConsole(DWORD value)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwWritten;

	char buffer[33];
	buffer[32] = '\0';  // Null-terminate the string
	int pos = 31;

	// Convert the DWORD to a string
	do {
		buffer[pos] = '0' + (value % 10);
		value /= 10;
		pos--;
	} while (value != 0);

	WriteConsoleA(hConsole, buffer + pos + 1, 32 - pos - 1, &dwWritten, NULL);
}

void Tools::ExitProgram(const char* message)
{
    MessageBoxA(NULL, message, "error", MB_ICONWARNING);
    ExitProcess(-1);
}

DWORD Tools::GetPID(const char* process) 
{
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

DWORD Tools::CreateRandomNumber(DWORD dwSeed, API::API_ACCESS& api)
{
	ULONG random = dwSeed;
	return api.func.pRtlRandomEx(&random);
}

DWORD Tools::GetRandomNumber(API::API_ACCESS& api)
{
	ULONG Random;
	POINT Point;

	ZeroMemory(&Point, sizeof(POINT));

	if (!api.func.pGetCursorPos(&Point))
		return 0;

	Random = (Point.x * Point.y) * api.func.pGetTickCount64();

	return CreateRandomNumber(Random, api);
}

void Tools::EnableDebugConsole()
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);

    if (!AllocConsole()) 
        return;

    if (hOut == INVALID_HANDLE_VALUE || hIn == INVALID_HANDLE_VALUE) 
        return;
   
    //SetConsoleTitle("Debug Console");
    SetStdHandle(STD_OUTPUT_HANDLE, hOut);
    SetStdHandle(STD_INPUT_HANDLE, hIn);
}
