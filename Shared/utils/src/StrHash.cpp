#include "utils/headers/StrHash.h"

constexpr int RandomCompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
};

// compile time Djb2 hashing function (WIDE)
constexpr DWORD HashStringDjb2W(const wchar_t* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}

// compile time Djb2 hashing function (ASCII)
constexpr DWORD HashStringDjb2A(const char* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}

// runtime hashing macros 
#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)
#define RTIME_HASHW( API ) HashStringDjb2W((const wchar_t*) API)



// compile time hashing macros (used to create variables)
#define CTIME_HASHA( API ) constexpr auto API##_Rotr32A = HashStringDjb2A((const char*) #API);
#define CTIME_HASHW( API ) constexpr auto API##_Rotr32W = HashStringDjb2W((const wchar_t*) L#API);

