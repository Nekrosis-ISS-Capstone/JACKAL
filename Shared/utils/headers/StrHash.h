#pragma once
#include <Windows.h>

#define SEED 5

constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;
constexpr int RandomCompileTimeSeed(void);

// compile time Djb2 hashing function (WIDE)
constexpr DWORD HashStringDjb2W(const wchar_t* String);

// compile time Djb2 hashing function (ASCII)
constexpr DWORD HashStringDjb2A(const char* String);