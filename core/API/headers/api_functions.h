#pragma once

#pragma once
#ifndef API_FUNCTIONS_H
#define API_FUNCTIONS_H

#include <Windows.h>
#include "winternl.h"

// NTDLL

typedef NTSTATUS(__stdcall* NtQueryInformationProcess_t)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);


typedef NTSTATUS(__stdcall* NtOpenProcess_t)(
	_Out_	 PHANDLE ProcessHandle,
	_In_	 ACCESS_MASK DesiredAccess,
	_In_	 POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ CLIENT_ID* ClientId
	);

typedef NTSTATUS(__stdcall* NtCreateProcess_t)(
	_Out_    PHANDLE			ProcessHandle,
	_In_     ACCESS_MASK		DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_     HANDLE				ParentProcess,
	_In_	 BOOLEAN			InheritObjectTable,
	_In_opt_ HANDLE				SectionHandle,
	_In_opt_ HANDLE				DebugPort,
	_In_opt_ HANDLE				ExceptionPort);

typedef NTSTATUS(__stdcall* NtTerminateProcess_t)(
	_In_opt_ HANDLE   ProcessHandle,
	_In_	 NTSTATUS ExitStatus);

typedef NTSTATUS(__stdcall* NtCreateThread_t)(
	_Out_ PHANDLE			   ThreadHandle,
	_In_  ACCESS_MASK		   DesiredAccess,
	_In_  POBJECT_ATTRIBUTES   ObjectAttributes,
	_In_  HANDLE			   ProcessHandle,
	_Out_ LPVOID			   ClientId,
	_In_  PCONTEXT			   ThreadContext,
	_In_  LPVOID			   InitialTeb,
	_In_  BOOLEAN			   CreateSuspended);

typedef NTSTATUS(__stdcall* LdrLoadDll_t)(
	_In_opt_  PWCHAR		  PathToFile,
	_In_opt_  ULONG			  Flags,
	_In_	  PUNICODE_STRING ModuleFilename,
	_Out_	  PHANDLE		  ModuleHandle);


typedef NTSTATUS(__stdcall* NtCreateFile_t)(
	_Out_	 PHANDLE FileHandle,
	_In_	 ACCESS_MASK DesiredAccess,
	_In_	 POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_	 PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_	 ULONG FileAttributes,
	_In_	 ULONG ShareAccess,
	_In_	 ULONG CreateDisposition,
	_In_	 ULONG	CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_	 ULONG EaLength
	);


typedef NTSTATUS(__stdcall* RtlInitUnicodeString_t)(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString
	);
typedef NTSTATUS(__stdcall *NtAllocateVirtualMemory_t) (
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
	);

typedef NTSTATUS(__stdcall *NtProtectVirtualMemory_t) (
	_In_    HANDLE  ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_    ULONG   NewProtect,
	_Out_   PULONG  OldProtect
	);

typedef NTSTATUS(__stdcall* NtFlushInstructionCache_t) (
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_     SIZE_T Length
	);

typedef NTSTATUS(__stdcall* LdrGetProcedureAddress_t) (
	_In_     PVOID        DllHandle,
	_In_opt_ PANSI_STRING ProcedureName,
	_In_opt_ ULONG        ProcedureNumber,
	_Out_    PVOID*		  ProcedureAddress
	);

// END NTDLL


// KERNEL32

typedef NTSTATUS (__stdcall* pSetFileInformationByHandle_t)(
	_In_ HANDLE                    hFile,
	_In_ FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
	_In_ LPVOID                    lpFileInformation,
	_In_ DWORD                     dwBufferSize
);

// END KERNEL32

#endif NTDLL_FUNCTIONS_H