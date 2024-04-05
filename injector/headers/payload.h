#pragma once
#include "Windows.h"

extern unsigned char g_HookShellCode[63];

bool LocateMemoryGap(IN HANDLE hProcess, OUT ULONG_PTR* puAddress, IN ULONG_PTR uExportedFuncAddress, IN size_t sPayloadSize);
bool InstallHook(IN HANDLE hProcess, IN void* pExportedFunc, IN void* pMainPayloadAddress);
bool WritePayloadBuffer(IN HANDLE hProcess, IN ULONG_PTR uAddress, IN ULONG_PTR uHookShellcode, IN size_t sHookShellcodeSize, IN ULONG_PTR uPayloadBuffer, IN size_t sPayloadSize);
void PatchHook(void* pExportedFunc);
