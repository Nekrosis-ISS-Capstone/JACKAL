#include "../headers/injection.h"
#include "utils/headers/Tools.h"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);

bool ManualMap(HANDLE hProc, const char* szDllFile)
{
	BYTE					*pSrcData		= nullptr;
	IMAGE_NT_HEADERS		*pOldNtHeader   = nullptr;
	IMAGE_OPTIONAL_HEADER   *pOldOptHeader	= nullptr;
	IMAGE_FILE_HEADER		*pOldFileHeader	= nullptr;
	BYTE					*pTargetBase	= nullptr;
	Tools					tools;

	DWORD dwCheck = 0;

	// Check if the file exists by attempting to get the file attributes
	if (!GetFileAttributesA(szDllFile))
	{
		tools.ShowError("File mapping: Cannot get DLL");
		return 0;
	}

	std::ifstream File(szDllFile, std::ios::binary | std::ios::ate); // Opening dll for read

	if (File.fail())
	{ 
		tools.ShowError("Failed to open ifstream", (int)File.rdstate());
		File.close();
		return 0;
	}

	auto FileSize = File.tellg(); // Get file size
	
	if (FileSize < 0x1000)
	{
		tools.ShowError("Filesize invalid");
		File.close();
		return 0;
	}

	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)]; // Retrieving pointer to a new byte array allocated on heap
	
	if (!pSrcData)
	{
		tools.ShowError("Internal Memory Allocation Failed");
		File.close();
		return 0;
	}

	// Write the byte array into memory
	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();

	// Check the magic number
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D)
	{
		tools.ShowError("Invalid file type");
		delete[] pSrcData;
		return 0;
	}
	 

	pOldNtHeader	= reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew); // e_lfanew points to the PE file signature
	pOldOptHeader	= &pOldNtHeader->OptionalHeader;
	pOldFileHeader	= &pOldNtHeader->FileHeader;

#ifdef _WIN64
	// Checking if DLL is 64 bit or not
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		tools.ShowError("Incorrect Platform");
		delete[] pSrcData;
		return 0;
	}
#else 
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		tools.ShowError("Incorrect Platform");
		delete[] pSrcData;
		return 0;
	}
#endif

	// Allocate memory in the target process

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(
		hProc,
		reinterpret_cast<void*>(pOldOptHeader->ImageBase), 
		pOldOptHeader->SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_EXECUTE_READWRITE
	));

	// If we cannot allocate memory to the image base
	if (!pTargetBase)
	{
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(
			hProc,
			nullptr,
			pOldOptHeader->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		));

		if (!pTargetBase)
		{
			tools.ShowError("External Memory Allocation Failed", GetLastError());
			delete[] pSrcData;
			return 0;
		}
	}

	MANUAL_MAPPING_DATA    data{ 0 };
	data.pLoadLibraryA	 = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader); // Points directly to the section after the optional header
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if ((pTargetBase + pSectionHeader->VirtualAddress) != 0)
			{
				if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
				{
					tools.ShowError("Cannot Map Sections", GetLastError());
					delete[] pSrcData;
					VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
					return 0;
				}
			}
		}
	}
	memcpy(pSrcData, &data, sizeof(data));
	WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr);

	delete[] pSrcData;

	void* pShellCode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if (!pShellCode)
	{
		tools.ShowError("External Memory Allocation Failed: ", GetLastError());
		VirtualFreeEx(hProc, pTargetBase,0, MEM_RELEASE);
		return 0;
	}

	WriteProcessMemory(hProc, pShellCode, Shellcode, 0x1000, nullptr);

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode), pTargetBase, 0, nullptr);

	if (!hThread)
	{
		tools.ShowError("Failed To Create Remote Thread: ", GetLastError());
		VirtualFreeEx(hProc, pTargetBase,0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);

		return 0;
	}
	CloseHandle(hThread);

	HINSTANCE hCheck = NULL;

	while (!hCheck)
	{
		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod; // At the end of the Shellcode function we set hMod to the base address so should be !0
	}

	VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);

	return true;
}

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData)
		return;
	
	BYTE* pBase					   =  reinterpret_cast<BYTE*>(pData); // The base address of the data to manual map
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	// Since we are injecting this code, we are not able to call functions usually, so we're passing the functions we need to the pData structure, then grab the pointer
	auto _LoadLibraryA	  =  pData->pLoadLibraryA;
	auto _GetProcAddress =  pData->pGetProcAddress;
	auto _DllMain		  =  reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		
		while (pRelocData->VirtualAddress)
		{
			// The amount of entries is the size of the block member minus the size of the two DWORDS / 2
			UINT AmountOfEntries = pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(WORD); // IMAGE_BASE_RELOCATION is 8 and WORD is 2
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress * ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}
	// Is there data in the import directory
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		IMAGE_IMPORT_DESCRIPTOR* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char* szMod			 = reinterpret_cast<char*>(pBase + pImportDescr->Name); // Contains the name of the current module we have loaded
			HINSTANCE hDll		 = _LoadLibraryA(szMod);
			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef  = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			// If imported by name these will be different
			if (!pFuncRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)); // Take the lower two bytes of pThunkRef to get the ordinal number of the function

				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}
	// Do TLS Callbacks
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		// While pCallBack and while pCallBack points to callbacks
		for (; pCallBack && *pCallBack; ++pCallBack)
			(*pCallBack)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}
	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase); // Allows us to check if the injection succeeded
}
