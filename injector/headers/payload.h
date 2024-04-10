#pragma once
#include "Windows.h"
#include "API/headers/api.h"

extern unsigned char g_HookShellCode[63];

bool LocateMemoryGap   (HANDLE hProcess, _Out_ ULONG_PTR* puAddress, uintptr_t uExportedFuncAddress, size_t sPayloadSize, API::API_ACCESS& api);
bool InstallHook	   (HANDLE hProcess, void* pExportedFunc, void* pMainPayloadAddress);
bool WritePayloadBuffer(HANDLE hProcess, ULONG_PTR uAddress, ULONG_PTR uHookShellcode, size_t sHookShellcodeSize, ULONG_PTR uPayloadBuffer, size_t sPayloadSize);
void PatchHook		   (void* pExportedFunc);
