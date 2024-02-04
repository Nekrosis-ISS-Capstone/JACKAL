#pragma once
#include <Windows.h>

#define SEED 5


constexpr int RandomCompileTimeSeed(void);

// compile time Djb2 hashing function (WIDE)
constexpr DWORD HashStringDjb2W(const wchar_t* string);

// compile time Djb2 hashing function (ASCII)
constexpr DWORD HashStringDjb2A(const char* string);


// runtime hashing macros 
#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)
#define RTIME_HASHW( API ) HashStringDjb2W((const wchar_t*) API)

// compile time hashing macros (used to create variables)
#define CTIME_HASHA( API ) constexpr auto API##_Rotr32A = HashStringDjb2A((const char*) #API);
#define CTIME_HASHW( API ) constexpr auto API##_Rotr32W = HashStringDjb2W((const wchar_t*) L#API);
