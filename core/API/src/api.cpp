// This file contains the function pointers to the ntapi/win32 api functions that are to be dynamically resolved at runtime

#include <API/headers/api.h>
#include <utils/headers/tools.h>
#include <utils/headers/CRTdefs.h>
#include <string>
#include <sstream>
#include <cstdint>
#include <unordered_map>
#include <functional>

#define SEED 5

using namespace API;

template <typename T, T Value>
struct integral_constant {
    static constexpr T value = Value;
};

API::APIResolver API::APIResolver::instance;


// Generate seed for string hashing
consteval int API::RandomCompileTimeSeed(void)
{
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

constexpr auto g_KEY = API::RandomCompileTimeSeed() % 0xFF; // Create seed variable

// compile time Djb2 hashing function (ASCII)
constexpr DWORD API::HashStringDjb2A(const char* string) {
    ULONG hash = (ULONG)g_KEY;
    INT c = 0;
    while ((c = *string++)) {
        hash = ((hash << SEED) + hash) + c;
    }

    return hash;
}

APIResolver::~APIResolver()
{
    FreeModules();
}

const API_ACCESS& APIResolver::GetAPIAccess() const
{
    return api;
}


namespace hashes
{
    /* NTDLL */
    constexpr DWORD NtQueryInformationProcess   = integral_constant<DWORD, HashStringDjb2A("NtQueryInformationProcess")>::value;
    constexpr DWORD NtCreateProcess             = integral_constant<DWORD, HashStringDjb2A("NtCreateProcess")>::value;
    constexpr DWORD NtCreateUserProcess         = integral_constant<DWORD, HashStringDjb2A("NtCreateUserProcess")>::value;
    constexpr DWORD NtTerminateProcess          = integral_constant<DWORD, HashStringDjb2A("NtTerminateProcess")>::value;
    constexpr DWORD NtCreateThread              = integral_constant<DWORD, HashStringDjb2A("NtCreateThread")>::value;
    constexpr DWORD LdrLoadDll                  = integral_constant<DWORD, HashStringDjb2A("LdrLoadDll")>::value;
    constexpr DWORD NtOpenProcess               = integral_constant<DWORD, HashStringDjb2A("NtOpenProcess")>::value;
    constexpr DWORD NtCreateFile                = integral_constant<DWORD, HashStringDjb2A("NtCreateFile")>::value;
    constexpr DWORD RtlInitUnicodeString        = integral_constant<DWORD, HashStringDjb2A("RtlInitUnicodeString")>::value;
    constexpr DWORD NtAllocateVirtualMemory     = integral_constant<DWORD, HashStringDjb2A("NtAllocateVirtualMemory")>::value;
    constexpr DWORD NtProtectVirtualMemory      = integral_constant<DWORD, HashStringDjb2A("NtProtectVirtualMemory")>::value;
    constexpr DWORD NtWriteVirtualMemory        = integral_constant<DWORD, HashStringDjb2A("NtWriteVirtualMemory")>::value;
    constexpr DWORD NtFlushInstructionCache     = integral_constant<DWORD, HashStringDjb2A("NtFlushInstructionCache")>::value;
    constexpr DWORD LdrGetProcedureAddress      = integral_constant<DWORD, HashStringDjb2A("LdrGetProcedureAddress")>::value;

    /* KERNEL32 */
    constexpr DWORD SetFileInformationByHandle = integral_constant<DWORD, HashStringDjb2A("SetFileInformationByHandle")>::value;

};



// This function will resolve all of the functions in our API_FUNCTIONS struct
void APIResolver::ResolveFunctions()
{
    api.func.pNtQueryInformationProcess  = reinterpret_cast<NtQueryInformationProcess_t> (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtQueryInformationProcess));
    api.func.pNtCreateProcess            = reinterpret_cast<NtCreateProcess_t>           (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtCreateProcess)); // Use NtCreateUserProcess instead
    api.func.pNtCreateUserProcess        = reinterpret_cast<NtCreateUserProcess_t>       (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtCreateUserProcess));
    api.func.pNtCreateThread             = reinterpret_cast<NtCreateThread_t>            (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtCreateThread));
    api.func.pLdrLoadDll                 = reinterpret_cast<LdrLoadDll_t>                (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::LdrLoadDll));
    api.func.pNtOpenProcess              = reinterpret_cast<NtOpenProcess_t>             (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtOpenProcess));
    api.func.pNtCreateFile               = reinterpret_cast<NtCreateFile_t>              (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtCreateFile));
    api.func.RtlInitUnicodeString        = reinterpret_cast<RtlInitUnicodeString_t>      (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::RtlInitUnicodeString));
    api.func.pNtAllocateVirtualMemory    = reinterpret_cast<NtAllocateVirtualMemory_t>   (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtAllocateVirtualMemory));
    api.func.pNtProtectVirtualMemory     = reinterpret_cast<NtProtectVirtualMemory_t>    (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtProtectVirtualMemory));
    api.func.pNtWriteVirtualMemory       = reinterpret_cast<NtWriteVirtualMemory_t>      (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtWriteVirtualMemory));
    api.func.pNtFlushInstructionCache    = reinterpret_cast<NtFlushInstructionCache_t>   (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtFlushInstructionCache));
    api.func.pLdrGetProcedureAddress     = reinterpret_cast<LdrGetProcedureAddress_t>    (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::LdrGetProcedureAddress));

    api.func.pSetFileInformationByHandle = reinterpret_cast<pSetFileInformationByHandle_t>(GetProcessAddressByHash(this->api.mod.Kernel32, hashes::SetFileInformationByHandle));
}

void *API::APIResolver::_(void** ppAddress)
{
    void *pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
    if (!pAddress)
        return NULL;

    // set the first 4 byte in pAddress to a random number
    *(int*)pAddress = RandomCompileTimeSeed() % 0xFF;

    *ppAddress = pAddress;

    return pAddress;
}


void APIResolver::LoadModules()
{
    this->api.mod.Kernel32 = LoadLibraryA("kernel32.dll");
    this->api.mod.Ntdll    = LoadLibraryA("ntdll.dll");
    

    if (!this->api.mod.Kernel32)
        return;
    if (!this->api.mod.Ntdll)
        return;
}

void API::APIResolver::IATCamo()
{
    void		*pAddress = NULL;
    int* dummy = (int*)_(&pAddress);

    if (*dummy > 350) {
        unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
        i = GetLastError();
        i = SetCriticalSectionSpinCount(NULL, NULL);
        i = GetWindowContextHelpId(NULL);
        i = GetWindowLongPtrW(NULL, NULL);
        i = RegisterClassW(NULL);
        i = IsWindowVisible(NULL);
        i = ConvertDefaultLocale(NULL);
        i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
        i = IsDialogMessageW(NULL, NULL);
    }
    HeapFree(GetProcessHeap(), 0, pAddress);
}

void APIResolver::FreeModules()
{

    if (this->api.mod.Kernel32)
        FreeLibrary(api.mod.Kernel32);
    if (this->api.mod.Ntdll)
        FreeLibrary(api.mod.Ntdll);
}

uintptr_t API::GetProcessAddressByHash(void* pBase, DWORD func)
{
    unsigned char* pBaseAddr = reinterpret_cast<unsigned char*>(pBase);

    PIMAGE_DOS_HEADER       pDosHeader  = nullptr;
    PIMAGE_NT_HEADERS       pNtHeaders  = nullptr;
    PIMAGE_FILE_HEADER      pFileHeader = nullptr;
    PIMAGE_OPTIONAL_HEADER  pOptHeader  = nullptr;
    PIMAGE_EXPORT_DIRECTORY pExportDir  = nullptr;

    DWORD exports_size = NULL;
    DWORD exports_rva  = NULL;

    pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBaseAddr);

    // Check magic number 
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        //tools.ShowError("Program Invalid: Incorrect DOS signature");
        return NULL;
    }

    pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pBaseAddr) + pDosHeader->e_lfanew); // Get pointer to the NT headers

    // Get File and Optional headers
    pFileHeader = &pNtHeaders->FileHeader;
    pOptHeader  = &pNtHeaders->OptionalHeader;


    // Verify that there is enough space for the NT headers
    if (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > pOptHeader->SizeOfImage)
    {
        //tools.ShowError("Program Invalid: Insufficient space for NT headers");
        return NULL;
    }

    // Verify that the optional header contains enough data directories
    if (pOptHeader->NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
    {
        // tools.ShowError("Program Invalid: Insufficient data directories");
        return NULL;
    }

    // Get the size and virtual address of the export directory
    exports_size = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    exports_rva  = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // Verify that the export directory is within the image boundaries
    if (exports_rva + exports_size > pOptHeader->SizeOfImage)
    {
        //tools.ShowError("Program Invalid: Export directory out of bounds");
        return NULL;
    }

    pExportDir   = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pBaseAddr) + exports_rva);   // Get the RVA
    DWORD* pEAT  = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfFunctions); // Address of Export Address Table functions
    DWORD* pENPT = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfNames);     // Address of Export Name Pointer Table 


    // Iterate through the functions in the export directory and check for a match
    for (unsigned int i = 0; i < pExportDir->NumberOfNames; ++i)
    {
        char* szNames = reinterpret_cast<char*>(pBaseAddr + reinterpret_cast<unsigned long*>(pBaseAddr + pExportDir->AddressOfNames)[i]);

        if (HashStringDjb2A(szNames) == func)
        {
            unsigned short usOrdinal = reinterpret_cast<unsigned short*>(pBaseAddr + pExportDir->AddressOfNameOrdinals)[i];
            uintptr_t address        = reinterpret_cast<uintptr_t>      (pBaseAddr + reinterpret_cast<unsigned long*>(pBaseAddr + pExportDir->AddressOfFunctions)[usOrdinal]);

            // Check if the function is forwarded
            if (address >= reinterpret_cast<uintptr_t>(pExportDir) && address < reinterpret_cast<uintptr_t>(pExportDir) + exports_size)
            {
                char cForwarderName[MAX_PATH] = { 0 };
                char* pcFunctionMod           = nullptr;
                char* pcFunctionName          = nullptr;
                DWORD dwDotOffset             = 0x0;

                memcpy(cForwarderName, reinterpret_cast<void*>(address), strlen(reinterpret_cast<char*>(address)));

                for (int j = 0; j < strlen(cForwarderName); j++)
                {
                    if (cForwarderName[j] == '.')
                    {
                        dwDotOffset = j;
                        cForwarderName[j] = NULL;
                        break;
                    }
                }

                pcFunctionMod  = cForwarderName;
                pcFunctionName = cForwarderName + dwDotOffset + 1;

                return GetProcessAddressByHash(LoadLibraryA(pcFunctionMod), HashStringDjb2A(pcFunctionName)); // TODO: use pLdrLoadDll
            }
            return address;
        }
    }

    return NULL;
}