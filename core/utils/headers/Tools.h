#pragma once
#ifndef TOOLS_H
#define TOOLS_H

#include <Windows.h>
#include <string>
#include "api/headers/api.h"


class Tools
{
public:
	// These functions are for debug purposes
	void ShowError(const char* error);
	DWORD GetRandomNumber(API::API_ACCESS& api);
	//void ShowError(const char* error, int errnum);
	//void DisplayMessage(const char* message, ...);
	void EnableDebugConsole();
	void PrintConsole(const char *message);

	void ExitProgram(const char* message);

	DWORD GetPID(const char* process);

private:
	DWORD CreateRandomNumber(DWORD Seed, API::API_ACCESS& api);

};
#endif TOOLS_H // !TOOLS_H


