#pragma once
#include "Windows.h"


bool LocateMemoryGap(IN HANDLE hProcess, OUT ULONG_PTR* puAddress, IN ULONG_PTR uExportedFuncAddress, IN SIZE_T sPayloadSize);