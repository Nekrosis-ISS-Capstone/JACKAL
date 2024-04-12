#ifndef API_H
#define API_H

#pragma once

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <API/headers/api_functions.h>

namespace API
{
	//typedef struct
	//{
	//	size_t	 FunctionHash;
	//	HMODULE* Module;
	//	LPVOID*  Function;
	//} API_T;

	typedef struct API_MODULES
	{
		// We will have a function to get handles to these modules via their hashed value 
		/*HMODULE Kernel32, Ntdll, User32, Wininet, Shell32, Advapi32, Urlmon, Ws2_32, Shlwapi;*/
		HMODULE Kernel32, Ntdll;


	}API_MODULES;

	// API_FUNCTIONS defines the function pointer variables of function types defined in *_functions.h
	typedef struct API_FUNCTIONS
	{
		/* NTDLL */
		NtQueryInformationProcess_t  pNtQueryInformationProcess;
		NtCreateProcess_t			 pNtCreateProcess; // Use pNtCreateUserProcess instead
		NtCreateUserProcess_t		 pNtCreateUserProcess;
		NtTerminateProcess_t		 pNtTerminateProcess;
		NtCreateThread_t			 pNtCreateThread;
		LdrLoadDll_t				 pLdrLoadDll;
		NtOpenProcess_t				 pNtOpenProcess;
		NtCreateFile_t			     pNtCreateFile;
		NtAllocateVirtualMemory_t    pNtAllocateVirtualMemory;
		NtProtectVirtualMemory_t	 pNtProtectVirtualMemory;
		NtWriteVirtualMemory_t		 pNtWriteVirtualMemory;
		NtFlushInstructionCache_t	 pNtFlushInstructionCache;
		NtDelayExecution_t			 pNtDelayExecution;
		LdrGetProcedureAddress_t     pLdrGetProcedureAddress;
		


		

		RtlInitUnicodeString_t		 RtlInitUnicodeString;



		/* KERNEL32 */

		SetFileInformationByHandle_t pSetFileInformationByHandle;
		//CreateToolhelp32Snapshot_t   pCreateToolhelp32Snapshot;
		//Process32First_t			 pProcess32First;
		//Process32First_t			 pProcess32Next;

	}API_FUNCTIONS;

	// This struct will be globally accessible through the class object make accessible publicly through APIResolver::GetAPIAccess()
	typedef struct API_ACCESS
	{
		API_MODULES   mod;
		API_FUNCTIONS func;

	}API_ACCESS;

	// ---- Hashing Functions ----
	consteval int RandomCompileTimeSeed(void);

	// compile time Djb2 hashing function (ASCII)
	constexpr DWORD HashStringDjb2A(const char* string);

	// ---------------------------------

	// Get process address by hash
	uintptr_t GetProcessAddressByHash(void* pBase, DWORD func);
	
	class APIResolver
	{
	public:
		APIResolver(const APIResolver&) = delete;
		~APIResolver();

		void FreeModules();
		const  API_ACCESS&  GetAPIAccess() const;
		static APIResolver& GetInstance() {return instance;}

		void LoadModules();
		void ResolveFunctions();
		void IATCamo();

	private:
		APIResolver() {
			this->IATCamo();
			this->LoadModules();
			this->ResolveFunctions();
		}; // Private constructor to ensure single instance of the class

		PVOID _(PVOID* ppAddress);

		static APIResolver instance; // An instance of this class
		API_ACCESS api;
	};
}




#endif // !API_H
