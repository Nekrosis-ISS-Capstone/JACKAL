 #include "../headers/api.h"
#include "utils/headers/Tools.h"
//#include "API/headers/ntdll.h"
#include <string>
#include <sstream>


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

	uintptr_t pFunctionsResolved[] = {0};
	int  nFunctionsResolved    =  0;

	// Iterate through the function pointers in the struct
	for (int i = 0; i < numFunctions; ++i)
	{ 
		// Get the function pointer at index i
		void *pFunc = *reinterpret_cast<PVOID*>((reinterpret_cast<char*>(&api) + i * sizeof(void*)));

		// Resolve the function address
		auto resolvedFunc = GetProcessAddress(hNtdll, reinterpret_cast<const char*>(pFunc));

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

API_MODULES LoadModules()
{
    API::API_MODULES modules;

    /*modules.Kernel32 = */

}

// Instead of using windows.h for these structures we should define them ourselves by creating custom_ntdll.h with only structure definitions with their dependancies 
uintptr_t API::GetProcessAddress(void *pBase, LPCSTR szFunc)
{

    unsigned char* pBaseAddr = reinterpret_cast<unsigned char*>(pBase);

    Tools tools; // For error reporting functionality

    PIMAGE_DOS_HEADER       pDosHeader  = nullptr;
    PIMAGE_NT_HEADERS       pNtHeaders  = nullptr;
    PIMAGE_FILE_HEADER      pFileHeader = nullptr;
    PIMAGE_OPTIONAL_HEADER  pOptHeader  = nullptr;
    PIMAGE_EXPORT_DIRECTORY pExportDir  = nullptr;

    DWORD exports_size = NULL;
    DWORD exports_rva  = NULL;

    // Get DOS header
    pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBaseAddr);

    // Check magic number 
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        tools.ShowError("Program Invalid: Incorrect DOS signature");
        return NULL;
    }

    pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pBaseAddr) + pDosHeader->e_lfanew); // Get pointer to the NT headers

    // Get File and Optional headers
    pFileHeader = &pNtHeaders->FileHeader;
    pOptHeader  = &pNtHeaders->OptionalHeader;


    // Verify that there is enough space for the NT headers
    if (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > pOptHeader->SizeOfImage)
    {
        tools.ShowError("Program Invalid: Insufficient space for NT headers");
        return NULL;
    }
    
    // Verify that the optional header contains enough data directories
    if (pOptHeader->NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
    {
        tools.ShowError("Program Invalid: Insufficient data directories");
        return NULL;
    }

    // Get the size and virtual address of the export directory
    exports_size = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    exports_rva  = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // Verify that the export directory is within the image boundaries
    if (exports_rva + exports_size > pOptHeader->SizeOfImage)
    {
        tools.ShowError("Program Invalid: Export directory out of bounds");
        return NULL;
    }

    pExportDir   = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pBaseAddr) + exports_rva);   // Get the RVA
    DWORD* pEAT  = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfFunctions); // Address of Export Address Table functions
    DWORD* pENPT = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfNames);     // Address of Export Name Pointer Table 

    // Iterate thro
    for (unsigned int i = 0; i < pExportDir->NumberOfNames; ++i)
    {

        char* szNames = reinterpret_cast<char*>(pBaseAddr + reinterpret_cast<char*>(pBaseAddr + pExportDir->AddressOfNames)[i]);
        if (!strcmp(szNames, szFunc))
        {
            unsigned short usOrdinal = reinterpret_cast<unsigned short*>(pBaseAddr + pExportDir->AddressOfNameOrdinals)[i];
            return reinterpret_cast<uintptr_t>(pBaseAddr + reinterpret_cast<unsigned long*>(pBaseAddr + pExportDir->AddressOfFunctions)[usOrdinal]);
        }
    }

    return NULL;
}



uintptr_t API::HdnGetProcAddress(void* hModule, LPCSTR wAPIName)
{
#if defined( _WIN32 )   
    unsigned char* lpBase = reinterpret_cast<unsigned char*>(hModule);
    IMAGE_DOS_HEADER* idhDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(lpBase);
    if (idhDosHeader->e_magic == 0x5A4D)
    {
#if defined( _M_IX86 )  
        IMAGE_NT_HEADERS32* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(lpBase + idhDosHeader->e_lfanew);
#elif defined( _M_AMD64 )  
        IMAGE_NT_HEADERS64* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(lpBase + idhDosHeader->e_lfanew);
#endif  
        if (inhNtHeader->Signature == 0x4550)
        {
            IMAGE_EXPORT_DIRECTORY* iedExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            for (register unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfNames; ++uiIter)
            {
                char* szNames = reinterpret_cast<char*>(lpBase + reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfNames)[uiIter]);
                if (!strcmp(szNames, wAPIName))
                {
                    unsigned short usOrdinal = reinterpret_cast<unsigned short*>(lpBase + iedExportDirectory->AddressOfNameOrdinals)[uiIter];
                    return reinterpret_cast<uintptr_t>(lpBase + reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfFunctions)[usOrdinal]);
                }
            }
        }
    }
#endif  
    return 0;
}

//void API::PrintFunctionNames(void* pBaseAddr)
//{
//    Tools tools; // For error reporting functionality
//
//    PIMAGE_DOS_HEADER       pDosHeader = nullptr;
//    PIMAGE_NT_HEADERS       pNtHeaders = nullptr;
//    PIMAGE_FILE_HEADER      pFileHeader = nullptr;
//    PIMAGE_OPTIONAL_HEADER  pOptHeader = nullptr;
//    PIMAGE_EXPORT_DIRECTORY pExportDir = nullptr;
//
//    DWORD exports_size = NULL;
//    DWORD exports_rva = NULL;
//
//    // Get DOS header
//    pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBaseAddr);
//
//    // Check magic number 
//    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
//    {
//        tools.ShowError("Program Invalid");
//        return;
//    }
//
//    pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pBaseAddr) + pDosHeader->e_lfanew); // Get pointer to the NT headers
//
//    // Get File and Optional headers
//    pFileHeader = &pNtHeaders->FileHeader;
//    pOptHeader = &pNtHeaders->OptionalHeader;
//
//    // Get the size and virtual address of the export directory
//    exports_size = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
//    exports_rva = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
//
//    pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pBaseAddr) + exports_rva);   // Get the RVA
//
//    DWORD* pEAT = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfFunctions); // Address of Export Address Table functions
//    DWORD* pENPT = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfNames);     // Address of Export Name Pointer Table 
//
//    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
//    {
//        // const char* currentFunctionName = reinterpret_cast<const char*>(reinterpret_cast<char*>(pBaseAddr) + pENPT[i]);
//        std::string name = reinterpret_cast<const char*>(reinterpret_cast<char*>(pBaseAddr) + pENPT[i]);
//        void* address = reinterpret_cast<void*>(reinterpret_cast<char*>(pBaseAddr) + pEAT[i]);
//
//        // Convert the address to a string
//        std::stringstream stream;
//        stream << address;
//        std::string addressString = stream.str();
//
//        // Convert the base address to a string
//        std::stringstream stream2;
//        stream2 << pBaseAddr;
//        std::string basestring = stream2.str();
//
//        std::string msg = name + ": " + addressString + " " + basestring;
//        /*tools.DisplayMessage(msg.c_str());*/
//
//        if (name == "NtQueryInformationProcess")
//        {
//            tools.DisplayMessage(name.c_str());
//            // Attempt to call the function if it matches the expected name
//            ptNtQueryInformationProcess_t ptNtQueryInformationProcess;
//            ptNtQueryInformationProcess = reinterpret_cast<ptNtQueryInformationProcess_t>(address);
//            PROCESS_BASIC_INFORMATION pbi;
//            ULONG returnLength;
//
//            try
//            {
//                NTSTATUS status = ptNtQueryInformationProcess(
//                    GetCurrentProcess(),
//                    ProcessBasicInformation,
//                    &pbi,
//                    sizeof(pbi),
//                    &returnLength
//                );
//
//                if (NT_SUCCESS(status))
//                {
//                    PVOID pPebBeingDebugged = (PPEB)__readgsqword(0x60);
//
//                    if (pPebBeingDebugged)
//                    {
//                        tools.ShowError("Being Debugged");
//                    }
//                }
//                else
//                {
//                    tools.ShowError("Failed with NTSTATUS code: ", status);
//                }
//            }
//            catch (const std::exception& e)
//            {
//                std::string error = "Exception: " + std::string(e.what());
//                tools.ShowError(error.c_str());
//            }
//        }
//    }
//}
//



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