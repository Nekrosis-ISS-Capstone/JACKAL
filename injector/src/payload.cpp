#include "utils/headers/CRTdefs.h"
#include "API/headers/api.h"
#include "intrin.h"
#include <winternl.h>

bool LocateMemoryGap(IN HANDLE hProcess, OUT ULONG_PTR* puAddress, IN ULONG_PTR uExportedFuncAddress, IN size_t sPayloadSize)
{
	size_t sTempSize = sPayloadSize;
	NTSTATUS status  = NULL;

	API::APIResolver &instance = API::APIResolver::GetInstance();

	auto api = instance.GetAPIAccess();


	for (void* uAddress = (uExportedFuncAddress & 0xFFFFFFFFFFF70000) - 0x70000000; uAddress < uExportedFuncAddress + 0x70000000; uAddress += 0x10000) 
	{
		if (!NT_SUCCESS((status = api.func.pNtAllocateVirtualMemory(hProcess, &uAddress, 0x00, &sTempSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))))
			continue;
	}
}