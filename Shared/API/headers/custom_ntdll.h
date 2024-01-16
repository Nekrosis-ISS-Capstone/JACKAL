// We'll see if this gets used in the future

//#pragma once
//#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
//typedef LONG KPRIORITY;
//
//typedef
//VOID
//(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (
//	VOID
//	);
//
//
//typedef struct _RTL_USER_PROCESS_PARAMETERS {
//	BYTE Reserved1[16];
//	PVOID Reserved2[10];
//	UNICODE_STRING ImagePathName;
//	UNICODE_STRING CommandLine;
//} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
//
//typedef struct _PEB_LDR_DATA {
//	BYTE Reserved1[8];
//	PVOID Reserved2[3];
//	LIST_ENTRY InMemoryOrderModuleList;
//} PEB_LDR_DATA, * PPEB_LDR_DATA;
//
//
//typedef struct _PEB {
//	BYTE Reserved1[2];
//	BYTE BeingDebugged;
//	BYTE Reserved2[1];
//	PVOID Reserved3[2];
//	PPEB_LDR_DATA Ldr;
//	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
//	PVOID Reserved4[3];
//	PVOID AtlThunkSListPtr;
//	PVOID Reserved5;
//	ULONG Reserved6;
//	PVOID Reserved7;
//	ULONG Reserved8;
//	ULONG AtlThunkSListPtr32;
//	PVOID Reserved9[45];
//	BYTE Reserved10[96];
//	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
//	BYTE Reserved11[128];
//	PVOID Reserved12[1];
//	ULONG SessionId;
//} PEB, * PPEB;
//
//typedef struct _PROCESS_BASIC_INFORMATION {
//	NTSTATUS ExitStatus;
//	PPEB PebBaseAddress;
//	ULONG_PTR AffinityMask;
//	KPRIORITY BasePriority;
//	ULONG_PTR UniqueProcessId;
//	ULONG_PTR InheritedFromUniqueProcessId;
//} PROCESS_BASIC_INFORMATION;
//
//
//typedef struct _UNICODE_STRING {
//	USHORT Length;
//	USHORT MaximumLength;
//	PWSTR  Buffer;
//} UNICODE_STRING;
//
//typedef UNICODE_STRING* PUNICODE_STRING;
//
//typedef enum PROCESSINFOCLASS {
//	ProcessBasicInformation = 0,
//	ProcessDebugPort = 7,
//	ProcessWow64Information = 26,
//	ProcessImageFileName = 27,
//	ProcessBreakOnTermination = 29
//} PROCESSINFOCLASS;
//
//typedef struct OBJECT_ATTRIBUTES
//{
//	ULONG Length;
//	HANDLE RootDirectory;
//	PUNICODE_STRING ObjectName;
//	ULONG Attributes;
//	PVOID SecurityDescriptor;		// PSECURITY_DESCRIPTOR;
//	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
//} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
