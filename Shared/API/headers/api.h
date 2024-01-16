#pragma once
#include <Windows.h>
#include "API/headers/ntdll_functions.h"
#include <string>

//#include "../API/ntdll.h"
namespace API
{
	typedef struct
	{
		size_t	 FunctionHash;
		HMODULE* Module;
		LPVOID*  Function;
	} API_T;

	typedef struct API_MODULES
	{
		// We will have a function to get handles to these modules via their hashed value 
		/*HMODULE Kernel32, Ntdll, User32, Wininet, Shell32, Advapi32, Urlmon, Ws2_32, Shlwapi;*/
		HMODULE Kernel32, Ntdll;


	}API_MODULES;

	// API_FUNCTIONS defines the function pointer variables of function types defined in *_functions.h
	typedef struct API_FUNCTIONS
	{
		// We need functionality to ensure the addresses of these function pointers are resolved via api hashing

		/* NTDLL */
		pNtQueryInformationProcess_t pNtQueryInformationProcess;
		pNtCreateProcess_t			 pNtCreateProcess;
		pNtTerminateProcess_t		 pNtTerminateProcess;
		pNtCreateThread_t			 pNtCreateThread;
		pLdrLoadDll_t				 pLdrLoadDll;

	}API_FUNCTIONS;

	typedef struct API_ACCESS
	{
		API_MODULES   mod;
		API_FUNCTIONS func;


	}API_ACCESS;

	uintptr_t GetProcessAddress(void* pBase, LPCSTR szFunc);
	uintptr_t GetProcessAddress(void* pBase, size_t szFunc);

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
