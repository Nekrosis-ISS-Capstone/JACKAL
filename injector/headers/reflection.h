#pragma once
#include "Windows.h"

typedef bool(__stdcall* DLL_MAIN)(HINSTANCE, DWORD, LPVOID);


void* ReflectiveShellcodeLdr(void* pParam, API::APIResolver& resolver);