#ifndef TOOLS_H
#define TOOLS_H

#pragma once
#include <Windows.h>
#include <string>


//extern void* __cdecl memset(void*, int, size_t);

// Force compiler to use our memset function
#pragma intrinsic(memset)
#pragma function(memset)

#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

class CRT
{
public:
	void _memcpy(void* dest, void* src, size_t sz);
	void* __cdecl _memset(void* dst, int value, size_t size);

};



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


