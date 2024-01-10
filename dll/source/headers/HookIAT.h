#pragma once
#include <Windows.h>

void* HookIAT(PBYTE pTarget, PCSTR lpModuleName, PCSTR lpApiName, void* pReplacement);

