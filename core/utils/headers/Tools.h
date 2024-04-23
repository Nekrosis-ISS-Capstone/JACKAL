#pragma once
#ifndef TOOLS_H
#define TOOLS_H

#include <Windows.h>
#include <string>

class Tools
{
public:
	// These functions are for debug purposes
	void ShowError(const char* error);
	//void ShowError(const char* error, int errnum);
	//void DisplayMessage(const char* message, ...);
	void EnableDebugConsole();
	void PrintConsole(const char *message);

	void ExitProgram(const char* message);

	DWORD GetPID(const char* process);

};
#endif TOOLS_H // !TOOLS_H


