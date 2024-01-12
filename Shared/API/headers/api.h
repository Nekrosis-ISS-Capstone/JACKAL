#pragma once
#include <Windows.h>
#include "API/headers/ntdll_functions.h"

//#include "../API/ntdll.h"
namespace API
{
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
		ptNtQueryInformationProcess_t ptNtQueryInformationProcess;

	}API_FUNCTIONS;

	typedef struct API_ACCESS
	{
		//API_INIT init;

		API_MODULES   mod;
		API_FUNCTIONS func;


	}API_ACCESS;
	//typedef struct API_MODULE
	//{
	//	DWORD	 ModuleHash;
	//	HMODULE* Module;
	//} API_MODULE;

	//typedef struct API_T
	//{
	//	//DWORD	 FunctionHash;
	//	HMODULE* Module;
	//	LPVOID* Function;
	//} API_T;


	uintptr_t GetProcessAddress(void* pBase, LPCSTR szFunc);

	class APIResolver
	{
	public:
		APIResolver();
		~APIResolver();
		
		API_MODULES FreeModules();
		const API_ACCESS& GetAPIAccess() const;
	private:


		API_MODULES LoadModules();
		void ResolveFunctions(API_MODULES hModuleHandle);

		API_ACCESS api;
	};
}
