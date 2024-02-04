#include "utils/headers/StrHash.h"


template <typename T, T Value>
struct integral_constant {
	static constexpr T value = Value;
};



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

constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;

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


constexpr const char* ntqueryinformationprocess_str = "NtQueryInformationProcess";
constexpr auto ntqueryinformationprocess = integral_constant<DWORD, HashStringDjb2A(ntqueryinformationprocess_str)>::value;

typedef struct {


}function_hashes;