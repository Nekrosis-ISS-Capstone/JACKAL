#pragma once

//#include "API/headers/ntdll.h"
#include <Windows.h>
#include <winternl.h>


typedef NTSTATUS(__stdcall* ptNtQueryInformationProcess_t)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);



//typedef struct _PROCESS_BASIC_INFORMATION {
//    NTSTATUS ExitStatus;
//    PPEB PebBaseAddress;
//    ULONG_PTR AffinityMask;
//    KPRIORITY BasePriority;
//    ULONG_PTR UniqueProcessId;
//    ULONG_PTR InheritedFromUniqueProcessId;
//} PROCESS_BASIC_INFORMATION;
