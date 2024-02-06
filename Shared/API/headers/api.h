#pragma once
#include <Windows.h>
#include "API/headers/ntdll_functions.h"


//#include "../API/ntdll.h"
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
		pNtQueryInformationProcess_t pNtQueryInformationProcess;
		pNtCreateProcess_t			 pNtCreateProcess;
		pNtTerminateProcess_t		 pNtTerminateProcess;
		pNtCreateThread_t			 pNtCreateThread;
		pLdrLoadDll_t				 pLdrLoadDll;

	}API_FUNCTIONS;

	// This struct will be globally accessible through the class object make accessible publicly through APIResolver::GetAPIAccess()
	typedef struct API_ACCESS
	{
		API_MODULES   mod;
		API_FUNCTIONS func;

	}API_ACCESS;

	// ---- Hashing Functions ----
	constexpr int RandomCompileTimeSeed(void);
	// compile time Djb2 hashing function (WIDE)
	constexpr DWORD HashStringDjb2W(const wchar_t* string);

	// compile time Djb2 hashing function (ASCII)
	constexpr DWORD HashStringDjb2A(const char* string);

	// ---------------------------------


	// Functions to get a function address by name and one to get by hash
	uintptr_t GetProcessAddress		 (void* pBase, LPCSTR szFunc); 
	uintptr_t GetProcessAddressByHash(void* pBase, DWORD func); 

	class APIResolver
	{
	public:
		APIResolver();
		~APIResolver();
		
		void FreeModules();
		const API_ACCESS& GetAPIAccess() const;
	private:

		void LoadModules();
		void ResolveFunctions(API_MODULES pModules);

		API_ACCESS api;
	};
}

static void checker(char* name, DWORD numbernames);