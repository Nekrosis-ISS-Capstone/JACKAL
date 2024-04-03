#pragma once
#include "Windows.h"

#include "API/headers/api.h"


typedef bool(__stdcall* DLL_MAIN)(HINSTANCE, DWORD, LPVOID);


void* ReflectiveShellcodeLdr(void* pParam, API::APIResolver& resolver);