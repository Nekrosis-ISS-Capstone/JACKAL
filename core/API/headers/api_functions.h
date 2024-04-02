#pragma once

#pragma once
#ifndef API_FUNCTIONS_H
#define API_FUNCTIONS_H

#include <Windows.h>
#include "winternl.h"

// NTDLL

typedef NTSTATUS(__stdcall* pNtQueryInformationProcess_t)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);


typedef NTSTATUS(__stdcall* pNtOpenProcess_t)(
	_Out_	 PHANDLE ProcessHandle,
	_In_	 ACCESS_MASK DesiredAccess,
	_In_	 POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ CLIENT_ID* ClientId
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


typedef NTSTATUS(__stdcall* pNtCreateFile_t)(
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


typedef void(__stdcall* RtlInitUnicodeString_t)(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString
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