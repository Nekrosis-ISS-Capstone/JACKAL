#pragma once
#ifndef API_FUNCTIONS_H
#define API_FUNCTIONS_H

#include <Windows.h>
#include "winternl.h"
#include <TlHelp32.h>

// dependencies



typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName, // Debugger specified
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		// PsCreateInitialState
		struct
		{
			union
			{
				ULONG InitFlags;
				struct
				{
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;

		// PsCreateFailOnSectionCreate
		struct
		{
			HANDLE FileHandle;
		} FailSection;

		// PsCreateFailExeFormat
		struct
		{
			USHORT DllCharacteristics;
		} ExeFormat;

		// PsCreateFailExeName
		struct
		{
			HANDLE IFEOKey;
		} ExeName;

		// PsCreateSuccess
		struct
		{
			union
			{
				ULONG OutputFlags;
				struct
				{
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE FileHandle;
			HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, * PPS_CREATE_INFO;


typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


// end dependencies




// NTDLL

typedef NTSTATUS(__stdcall* NtQueryInformationProcess_t)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);


typedef NTSTATUS(__stdcall* NtOpenProcess_t)(
	_Out_	 PHANDLE			ProcessHandle,
	_In_	 ACCESS_MASK		DesiredAccess,
	_In_	 POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ CLIENT_ID*			ClientId
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


typedef NTSTATUS(__stdcall* NtCreateUserProcess_t)(
	_Out_ PHANDLE			    ProcessHandle,
	_Out_ PHANDLE			    ThreadHandle,
	_In_ ACCESS_MASK		    ProcessDesiredAccess,
	_In_ ACCESS_MASK		    ThreadDesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
	_In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
	_In_ ULONG					ProcessFlags, // PROCESS_CREATE_FLAGS_*
	_In_ ULONG					ThreadFlags, // THREAD_CREATE_FLAGS_*
	_In_opt_ PVOID				ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
	_Inout_ PPS_CREATE_INFO		CreateInfo,
	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);



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
	_Out_	 PHANDLE					 FileHandle,
	_In_	 ACCESS_MASK				 DesiredAccess,
	_In_	 POBJECT_ATTRIBUTES			 ObjectAttributes,
	_Out_	 PIO_STATUS_BLOCK			 IoStatusBlock,
	_In_opt_ PLARGE_INTEGER				 AllocationSize,
	_In_	 ULONG						 FileAttributes,
	_In_	 ULONG						 ShareAccess,
	_In_	 ULONG						 CreateDisposition,
	_In_	 ULONG					     CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_	 ULONG						 EaLength
	);


typedef NTSTATUS(__stdcall* RtlInitUnicodeString_t)(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString
	);
typedef NTSTATUS(__stdcall* NtAllocateVirtualMemory_t) (
	_In_    HANDLE    ProcessHandle,
	_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
	);

typedef NTSTATUS(__stdcall* NtProtectVirtualMemory_t) (
	_In_    HANDLE  ProcessHandle,
	_Inout_ PVOID*  BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_    ULONG   NewProtect,
	_Out_   PULONG  OldProtect
	);

typedef NTSTATUS(__stdcall* NtWriteVirtualMemory_t) (
	_In_	  HANDLE  ProcessHandle,
	_In_opt_  PVOID   BaseAddress,
	_In_reads_bytes_(BufferSize) PVOID Buffer,
	_In_	  SIZE_T  BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
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

typedef NTSTATUS(__stdcall* NtDelayExecution_t)(
	BOOLEAN              Alertable,
	PLARGE_INTEGER       DelayInterval
	);

// END NTDLL


// KERNEL32

typedef NTSTATUS (__stdcall* SetFileInformationByHandle_t)(
	_In_ HANDLE                    hFile,
	_In_ FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
	_In_ LPVOID                    lpFileInformation,
	_In_ DWORD                     dwBufferSize
);

typedef HANDLE(WINAPI* CreateToolhelp32Snapshot_t)(	
	_In_ DWORD dwFlags,
	_In_ DWORD th32ProcessID
);

typedef BOOL(__stdcall* Process32First_t)(
	_In_	HANDLE			hSnapshot,
	_Inout_ PROCESSENTRY32* lppe
);

typedef BOOL(__stdcall* Process32Next_t)(
	_In_	HANDLE			hSnapshot,
	_Inout_ PROCESSENTRY32* lppe
);

// END KERNEL32


// BCRYPT

typedef NTSTATUS(__stdcall* BCryptSetProperty_t)(
	_Inout_   PVOID			hObject,
	_In_      LPCWSTR       pszProperty,
	_In_      PUCHAR        pbInput,
	_In_      ULONG         cbInput,
	_In_      ULONG         dwFlags
);

typedef NTSTATUS (__stdcall* BCryptGetProperty_t)(
	_In_  PVOID			hObject,
	_In_  LPCWSTR       pszProperty,
	_In_ PUCHAR         pbOutput,
	_In_  ULONG         cbOutput,
	_In_ ULONG*			pcbResult,
	_In_  ULONG         dwFlags
);

typedef NTSTATUS (__stdcall *BCryptOpenAlgorithmProvider_t)(
	_Out_ PVOID*	phAlgorithm,
	_In_  LPCWSTR   pszAlgId,
	_In_  LPCWSTR   pszImplementation,
	_In_  ULONG     dwFlags
);

typedef NTSTATUS(__stdcall* BCryptGenerateSymmetricKey_t)(
	_Inout_  PVOID		hAlgorithm,
	_Out_    PVOID*		phKey,
	_Out_opt_ PUCHAR    pbKeyObject,
	_In_     ULONG      cbKeyObject,
	_In_     PUCHAR     pbSecret,
	_In_     ULONG      cbSecret,
	_In_     ULONG      dwFlags
);

typedef NTSTATUS(__stdcall* BCryptEncrypt_t)(
	_Inout_            PVOID			 hKey,
	_In_               PUCHAR            pbInput,
	_In_               ULONG             cbInput,
	_In_opt_           void*			 pPaddingInfo,
	_Inout_opt_        PUCHAR            pbIV,
	_In_               ULONG             cbIV,
	_Out_opt_          PUCHAR            pbOutput,
	_In_               ULONG             cbOutput,
	_Out_              ULONG*			 pcbResult,
	_In_               ULONG             dwFlags
);

typedef NTSTATUS(__stdcall* BCryptDecrypt_t)(
	_Inout_            PVOID		     hKey,
	_In_               PUCHAR            pbInput,
	_In_               ULONG             cbInput,
	_In_opt_           VOID*			 pPaddingInfo,
	_Inout_opt_        PUCHAR            pbIV,
	_In_               ULONG             cbIV,
	_Out_opt_          PUCHAR            pbOutput,
	_In_               ULONG             cbOutput,
	_Out_              ULONG*			 pcbResult,
	_In_               ULONG             dwFlags
	);


typedef NTSTATUS(__stdcall* BCryptDestroyKey_t)(
	_Inout_ PVOID hKey
);

typedef NTSTATUS(__stdcall* BCryptCloseAlgorithmProvider_t)(
	_Inout_ PVOID			  hAlgorithm,
	_In_    ULONG             dwFlags
);

// END BCRYPT

#endif NTDLL_FUNCTIONS_H