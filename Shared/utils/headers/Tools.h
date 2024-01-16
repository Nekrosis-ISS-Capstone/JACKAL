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
	consteval std::string XorStr(std::string input);
}; 
