// This file contains the function pointers to the ntapi/win32 api functions that are to be dynamically resolved at runtime


#include "../headers/api.h"
#include "utils/headers/Tools.h"
#include <string>
#include <sstream>

using namespace API;


// API_INIT CLASS

APIResolver::APIResolver()
{
    //API_ACCESS api = GetAPIAccess();
    this->LoadModules();
    this->ResolveFunctions(api.mod);
}
APIResolver::~APIResolver()
{
    FreeModules();
}


const API_ACCESS& APIResolver::GetAPIAccess() const 
{
    return api;
}

// This function will resolve all of the functions in our API_FUNCTIONS struct
void APIResolver::ResolveFunctions(API_MODULES hModuleHandle)
{
	/*API_FUNCTIONS api;*/
	Tools tools;
    //constexpr std::string yar = "NtQueryInformationProcess";
    //constexpr std::string name = tools.EarlyHash(yar);

	// Get the number of function pointers in the struct
	size_t numFunctions = sizeof(API_FUNCTIONS) / sizeof(PVOID);

    tools.ShowError("Number of functions: ", (int)numFunctions);

    constexpr auto burns = tools.EarlyHash("NtQueryInformationProcess");


    API_T ApiList[]
    {
        {},
        {},
        {},
    };


    // we have to recreate this functionality
    api.func.pNtQueryInformationProcess = reinterpret_cast<pNtQueryInformationProcess_t>(GetProcessAddress(this->api.mod.Ntdll, "NtQueryInformationProcess"));

    

	//uintptr_t pFunctionsResolved[] = {0};
	//int  nFunctionsResolved        =  0;

 //   for (int i = 0; i < sizeof(this->api.mod) / sizeof(HMODULE); i++)
 //   {
 //       // Iterate through the function pointers in the struct
 //       for (int i = 0; i < numFunctions; ++i)
 //       {
 //           // Get the function pointer at index i
 //           void* pFunc = *reinterpret_cast<PVOID*>((reinterpret_cast<char*>(&this->api.func) + i * sizeof(void*)));

 //           // Resolve the function address
 //           auto resolvedFunc = GetProcessAddress(this->api.mod.Ntdll, reinterpret_cast<const char*>(pFunc));

 //           if (!resolvedFunc)
 //           {
 //               // Handle the case where a function is not found
 //               tools.ShowError("Failed to find function");
 //               exit(-1);
 //           }
 //           nFunctionsResolved++;
 //           pFunctionsResolved[i] = resolvedFunc;
 //           // Now 'resolvedFunc' contains the address of the function, you can use it as needed
 //       }
 //   }
	//tools.ShowError("number of functions resolved: ", nFunctionsResolved );

}

void APIResolver::LoadModules()
{
    Tools tools;

    api.mod.Kernel32 = LoadLibraryA("kernel32.dll");
    api.mod.Ntdll    = LoadLibraryA("ntdll.dll");

    if (!api.mod.Kernel32) 
        tools.ShowError("Failed to get handle to kernel32");
    if (!api.mod.Ntdll) 
        tools.ShowError("Failed to get handle to Ntdll");
}


void APIResolver::FreeModules()
{
    if (api.mod.Kernel32)
        FreeLibrary(api.mod.Kernel32);
    if (api.mod.Ntdll)
        FreeLibrary(api.mod.Ntdll);
}

// END API_INIT CLASS



// Custom GetProcAddress implementation to avoid usage of winapi functions
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

        char* szNames = reinterpret_cast<char*>(pBaseAddr + reinterpret_cast<unsigned long*>(pBaseAddr + pExportDir->AddressOfNames)[i]);
        if (!strcmp(szNames, szFunc))
        {
            unsigned short usOrdinal = reinterpret_cast<unsigned short*>(pBaseAddr + pExportDir->AddressOfNameOrdinals)[i];
            return reinterpret_cast<uintptr_t>(pBaseAddr + reinterpret_cast<unsigned long*>(pBaseAddr + pExportDir->AddressOfFunctions)[usOrdinal]);
        }
    }

    return NULL;
}

//uintptr_t API::GetProcessAddress(void* pBase, size_t szFunc)
//{
//
//    unsigned char* pBaseAddr = reinterpret_cast<unsigned char*>(pBase);
//
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
//        tools.ShowError("Program Invalid: Incorrect DOS signature");
//        return NULL;
//    }
//
//    pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pBaseAddr) + pDosHeader->e_lfanew); // Get pointer to the NT headers
//
//    // Get File and Optional headers
//    pFileHeader = &pNtHeaders->FileHeader;
//    pOptHeader = &pNtHeaders->OptionalHeader;
//
//
//    // Verify that there is enough space for the NT headers
//    if (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > pOptHeader->SizeOfImage)
//    {
//        tools.ShowError("Program Invalid: Insufficient space for NT headers");
//        return NULL;
//    }
//
//    // Verify that the optional header contains enough data directories
//    if (pOptHeader->NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
//    {
//        tools.ShowError("Program Invalid: Insufficient data directories");
//        return NULL;
//    }
//
//    // Get the size and virtual address of the export directory
//    exports_size = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
//    exports_rva = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
//
//    // Verify that the export directory is within the image boundaries
//    if (exports_rva + exports_size > pOptHeader->SizeOfImage)
//    {
//        tools.ShowError("Program Invalid: Export directory out of bounds");
//        return NULL;
//    }
//
//    pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pBaseAddr) + exports_rva);   // Get the RVA
//    DWORD* pEAT = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfFunctions); // Address of Export Address Table functions
//    DWORD* pENPT = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfNames);     // Address of Export Name Pointer Table 
//
//    // Iterate thro
//    for (unsigned int i = 0; i < pExportDir->NumberOfNames; ++i)
//    {
//
//        char* szNames = reinterpret_cast<char*>(pBaseAddr + reinterpret_cast<unsigned long*>(pBaseAddr + pExportDir->AddressOfNames)[i]);
//        if (!strcmp(szNames, szFunc))
//        {
//            unsigned short usOrdinal = reinterpret_cast<unsigned short*>(pBaseAddr + pExportDir->AddressOfNameOrdinals)[i];
//            return reinterpret_cast<uintptr_t>(pBaseAddr + reinterpret_cast<unsigned long*>(pBaseAddr + pExportDir->AddressOfFunctions)[usOrdinal]);
//        }
//    }
//
//    return NULL;
//}