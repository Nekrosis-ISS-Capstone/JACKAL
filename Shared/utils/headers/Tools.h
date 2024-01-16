#pragma once
#include <Windows.h>
#include <string>


class Tools
{
public:
	void ShowError(const char *error);
	void ShowError(const char *error, int errnum);
	void DisplayMessage(const char *message, ...);
	void EnableDebugConsole();

	consteval size_t EarlyHash(const char* str, size_t h = 14695981039346656037ull);
		      size_t LateHash (const char* str, size_t h = 14695981039346656037ull);
};
