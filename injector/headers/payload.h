#ifndef PAYLOAD_H
#define PAYLOAD_H

#pragma once
#include "Windows.h"
#include "API/headers/api.h"

extern unsigned char hook[63];
extern unsigned char payload[106];

class Payload
{
public:
	Payload(DWORD process, API::API_ACCESS& api, const char* dll, const char* function);

private:
	bool LocateMemoryGap   (HANDLE hProcess, _Out_ ULONG_PTR* puAddress, uintptr_t uExportedFuncAddress, size_t sPayloadSize, API::API_ACCESS& api);
	bool InstallHook	   (HANDLE hProcess, void* pExportedFunc, void* pMainPayloadAddress);
	bool WritePayloadBuffer(HANDLE hProcess, ULONG_PTR uAddress, ULONG_PTR uHookShellcode, size_t sHookShellcodeSize, ULONG_PTR uPayloadBuffer, size_t sPayloadSize);
	void PatchHook		   (void* pExportedFunc);
};


#endif 