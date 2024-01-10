#include "../headers/api.h"
#include "utils/headers/Tools.h"
//#include "API/headers/ntdll.h"


// This file contains the function pointers to the ntapi/win32 api functions that are to be dynamically resolved at runtime

using namespace API;

// This function will resolve all of the functions in our struct 
void API_ACCESS::ResolveFunctions(HMODULE hModuleHandle, void* pFunc, const char* szFunc)
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	API_FUNCTIONS api;
	Tools tools;

	// Get the number of function pointers in the struct
	size_t numFunctions = sizeof(API_FUNCTIONS) / sizeof(PVOID);

	void *pFunctionsResolved[] = {0};
	int  nFunctionsResolved    =  0;

	// Iterate through the function pointers in the struct
	for (int i = 0; i < numFunctions; ++i)
	{ 
		// Get the function pointer at index i
		void *pFunc = *reinterpret_cast<PVOID*>((reinterpret_cast<char*>(&api) + i * sizeof(void*)));

		// Resolve the function address
		void *resolvedFunc = GetProcessAddress(hNtdll, reinterpret_cast<const char*>(pFunc));

		if (!resolvedFunc)
		{
			// Handle the case where a function is not found
			tools.ShowError("Failed to find function");
			exit(-1);
		}
		nFunctionsResolved++;
		pFunctionsResolved[i] = resolvedFunc;
		// Now 'resolvedFunc' contains the address of the function, you can use it as needed
	}
	
	tools.ShowError("number of functions resolved: ", nFunctionsResolved );

}



//// Instead of using windows.h for these structures we should define them ourselves by creating custom_ntdll.h with only structure definitions with their dependancies 
//void *API::GetProcessAddress(void *pBaseAddr, const char* func)
//{
//    Tools tools; // For error reporting functionality
//
//    PIMAGE_DOS_HEADER       pDosHeader  = nullptr;
//    PIMAGE_NT_HEADERS       pNtHeaders  = nullptr;
//    PIMAGE_FILE_HEADER      pFileHeader = nullptr;
//    PIMAGE_OPTIONAL_HEADER  pOptHeader  = nullptr;
//    PIMAGE_EXPORT_DIRECTORY pExportDir  = nullptr;
//
//    DWORD exports_size = NULL;
//    DWORD exports_rva  = NULL;
//
//    // Get DOS header
//    pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBaseAddr);
//
//    // Check magic number 
//    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
//    {
//        tools.ShowError("Program Invalid");
//        return nullptr;
//    }
//
//    pNtHeaders  = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pBaseAddr) + pDosHeader->e_lfanew); // Get pointer to the NT headers
//    
//    // Get File and Optional headers
//    pFileHeader = &pNtHeaders->FileHeader;
//    pOptHeader  = &pNtHeaders->OptionalHeader;
//
//    // Get the size and virtual address of the export directory
//    exports_size = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
//    exports_rva  = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
//
//    pExportDir   = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pBaseAddr) + exports_rva);   // Get the RVA
//
//    DWORD* pEAT  = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfFunctions); // Address of Export Address Table functions
//    DWORD* pENPT = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfNames);     // Address of Export Name Pointer Table 
//
//    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
//    {
//        const char* currentFunctionName = reinterpret_cast<const char*>(reinterpret_cast<char*>(pBaseAddr) + pENPT[i]);
//
//        if (strcmp(currentFunctionName, func) == 0)
//            return reinterpret_cast<void*>(reinterpret_cast<char*>(pBaseAddr) + pEAT[i]); // If function name matches, return the address from the export address table
//    }
//
//    return nullptr;
//}
void* API::GetProcessAddress(void* pBaseAddr, const char* func)
{
    Tools tools; // For error reporting functionality

    PIMAGE_DOS_HEADER       pDosHeader = nullptr;
    PIMAGE_NT_HEADERS       pNtHeaders = nullptr;
    PIMAGE_FILE_HEADER      pFileHeader = nullptr;
    PIMAGE_OPTIONAL_HEADER  pOptHeader = nullptr;
    PIMAGE_EXPORT_DIRECTORY pExportDir = nullptr;

    DWORD exports_size = NULL;
    DWORD exports_rva = NULL;

    // Get DOS header
    pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBaseAddr);

    // Check magic number
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        tools.ShowError("Invalid DOS signature");
        return nullptr;
    }

    pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pBaseAddr) + pDosHeader->e_lfanew); // Get pointer to the NT headers

    // Check if NT headers are valid
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        tools.ShowError("Invalid NT signature");
        return nullptr;
    }

    // Get File and Optional headers
    pFileHeader = &pNtHeaders->FileHeader;
    pOptHeader = &pNtHeaders->OptionalHeader;

    // Get the size and virtual address of the export directory
    exports_size = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    exports_rva = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // Check if the export directory is valid
    if (exports_rva == 0 || exports_size == 0)
    {
        tools.ShowError("No export directory found");
        return nullptr;
    }

    pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pBaseAddr) + exports_rva); // Get the RVA

    DWORD* pEAT = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfFunctions); // Address of Export Address Table functions
    DWORD* pENPT = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfNames);     // Address of Export Name Pointer Table

    // Inside the loop where you search for the function name
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
    {
        const char* currentFunctionName = reinterpret_cast<const char*>(reinterpret_cast<char*>(pBaseAddr) + pENPT[i]);

        if (strcmp(currentFunctionName, func) == 0)
        {
            // Check if the index is within the bounds of the AddressOfFunctions table
            if (pEAT[i] < exports_rva || pEAT[i] >= exports_rva + exports_size)
            {
                tools.ShowError("Function address is outside the valid range");
                const char* errorMsg = "Function address is outside the valid range\n"
                    "Function Name: %s\n"
                    "Index: %d\n"
                    "Address in EAT: %08X\n"
                    "Valid Range: [%08X, %08X)";
                tools.DisplayMessage(errorMsg, func, i, pEAT[i], exports_rva, exports_rva + exports_size);
                return nullptr;
            }

            // Return the address from the export address table
            return reinterpret_cast<void*>(reinterpret_cast<char*>(pBaseAddr) + pEAT[i]);
        }
    }

    tools.ShowError("Function not found in the export table");
    const char* errorMsg = "Function not found in the export table\nFunction Name: %s";
    tools.DisplayMessage(errorMsg, func);
    return nullptr;

}



//PVOID API::GetProcAddress_BinarySearch(PVOID base, const char* func) {
//    Tools tools;
//    PIMAGE_DOS_HEADER      dos         = (PIMAGE_DOS_HEADER)base;
//    PIMAGE_FILE_HEADER     head        = (PIMAGE_FILE_HEADER)((char*)base + dos->e_lfanew + sizeof(DWORD));
//    PIMAGE_OPTIONAL_HEADER opt_head    = (PIMAGE_OPTIONAL_HEADER)(head + 1);
//    ULONG                  export_size = opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
//    ULONG                  export_rva  = opt_head->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
//
//    if (!export_size) {
//        tools.ShowError("Export directory size is zero.");
//        return NULL;
//    }
//
//    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((char*)base + export_rva);
//
//    DWORD* name_rva     = (PDWORD)((char*)base + exports->AddressOfNames);
//    DWORD* function_rva = (PDWORD)((char*)base + exports->AddressOfFunctions);
//    WORD*  ordinal      = (PWORD) ((char*)base + exports->AddressOfNameOrdinals);
//
//    if (name_rva == nullptr || function_rva == nullptr || ordinal == nullptr) {
//        tools.ShowError("Invalid pointers in the export directory.");
//        return NULL;
//    }
//
//    // binary search
//    unsigned long right, left, middle;
//    right = exports->NumberOfNames;
//    left = 0;
//
//    //tools.ShowError("here", exports->NumberOfNames);
//
//    while (right != left) {
//        middle = left + ((right - left) >> 1);
//
//        if (name_rva[middle] >= export_size || name_rva[middle] + sizeof(char) > export_size) {
//            tools.ShowError("Invalid name_rva offset.");
//            return NULL;
//        }
//
//        const char* functionName = (const char*)((char*)base + name_rva[middle]);
//        int result = strcmp(functionName, func);
//
//        if (!result)
//            return (PVOID)((char*)base + function_rva[ordinal[middle]]);
//        else if (result < 0) {
//            left = middle;
//        }
//        else {
//            right = middle;
//        }
//    }
//
//    tools.ShowError("Function not found: ");
//    return NULL;
//}
//
//void API::BinarySearch()
//{ 
//	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
//	API_FUNCTIONS api;
//	Tools tools;
//
//	// Get the number of function pointers in the struct
//	size_t numFunctions = sizeof(API_FUNCTIONS) / sizeof(PVOID);
//
//	void *pFunctionsResolved[] = {0};
//	int nFunctionsResolved = 0;
//
//	// Iterate through the function pointers in the struct
//	for (int i = 0; i < numFunctions; ++i)
//	{
//		// Get the function pointer at index i
//		PVOID funcPtr = *reinterpret_cast<PVOID*>((reinterpret_cast<char*>(&api) + i * sizeof(PVOID)));
//
//		// Resolve the function address
//		PVOID resolvedFunc = GetProcAddress_BinarySearch(hNtdll, reinterpret_cast<const char*>(funcPtr));
//
//		if (!resolvedFunc)
//		{
//			// Handle the case where a function is not found
//			tools.ShowError("Failed to find function");
//			exit(-1);
//		}
//		nFunctionsResolved++;
//		pFunctionsResolved[i] = resolvedFunc;
//		// Now 'resolvedFunc' contains the address of the function, you can use it as needed
//	}
//	
//	tools.ShowError("number of functions resolved: ", nFunctionsResolved );
//}