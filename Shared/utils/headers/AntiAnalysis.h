#pragma once
#include <Windows.h>
#include "API/headers/api.h"
#include "utils/headers/Tools.h"

class AntiAnalysis
{
	bool Peb();

public:
	bool PebCheck(/*DWORD64& nStartTime*/);

};