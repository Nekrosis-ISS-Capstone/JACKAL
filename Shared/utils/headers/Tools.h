#ifndef TOOLS_H
#define TOOLS_H

#pragma once
#include <Windows.h>
#include <string>

class Logging
{
public:
	// These functions are for debug purposes
	void ShowError(const char *error);
	void ShowError(const char *error, int errnum);
	void DisplayMessage(const char *message, ...);
	void EnableDebugConsole();
	void PrintConsole(std::string message);



};
#endif TOOLS_H // !TOOLS_H


