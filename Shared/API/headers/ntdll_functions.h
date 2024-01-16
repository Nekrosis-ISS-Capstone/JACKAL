#pragma once

#include "API/headers/custom_ntdll.h" // This might get used in the future
//#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(__stdcall* pNtQueryInformationProcess_t)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);


typedef NTSTATUS(__stdcall* pNtCreateProcess_t)(
	_Out_    PHANDLE			ProcessHandle,
	_In_     ACCESS_MASK		DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_     HANDLE				ParentProcess,
	_In_	 BOOLEAN			InheritObjectTable, 
	_In_opt_ HANDLE				SectionHandle,
	_In_opt_ HANDLE				DebugPort,
	_In_opt_ HANDLE				ExceptionPort);

typedef NTSTATUS(__stdcall* pNtTerminateProcess_t)(
	_In_opt_ HANDLE   ProcessHandle,
	_In_	 NTSTATUS ExitStatus);

typedef NTSTATUS(__stdcall* pNtCreateThread_t)(
	_Out_ PHANDLE			   ThreadHandle,
	_In_  ACCESS_MASK		   DesiredAccess,
	_In_  POBJECT_ATTRIBUTES   ObjectAttributes,
	_In_  HANDLE			   ProcessHandle,
	_Out_ LPVOID			   ClientId,
	_In_  PCONTEXT			   ThreadContext,
	_In_  LPVOID			   InitialTeb,
	_In_  BOOLEAN			   CreateSuspended);

typedef NTSTATUS(__stdcall* pLdrLoadDll_t)(
	_In_opt_  PWCHAR		  PathToFile,
	_In_opt_  ULONG			  flags,
	_In_	  PUNICODE_STRING moduleFileName,
	_Out_	  PHANDLE		  moduleHandle);



