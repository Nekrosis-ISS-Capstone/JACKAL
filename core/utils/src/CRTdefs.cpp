#pragma once
#include <Windows.h>
#include <stddef.h>
#include "utils/headers/CRTdefs.h"



// Implementation of the atexit function
int atexit(void (*function)(void)) {
	// Check if there is space in the array
	if (sAtExitFuncs < MAX_ATEXIT_FUNCS) {
		// Add the function to the array
		AtExitFuncs[sAtExitFuncs++].func = function;
		return 0; // Success
	}
	else {
		return 1; // Failure, array is full
	}
}

// Function to call all registered functions on program exit
void call_atexit_funcs() 
{
	// Call each registered function in reverse order
	for (size_t i = sAtExitFuncs; i > 0; --i) {
		AtExitFuncs[i - 1].func();
	}
}

size_t __cdecl strlen(const char* str)
{
	int count = 0;
	while (str[count] != '\0' || '\n')
		count++;

	return count;
}

int __cdecl strcmp(_In_ LPCSTR String1, _In_ LPCSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}

void* __cdecl memset(void* dest, int val, size_t sz) 
{
	unsigned char* p = (unsigned char*)dest;
	while (sz > 0) {
		*p = (unsigned char)val;
		p++;
		sz--;
	}
	return dest;
}

void* __cdecl memcpy(void* dest, const void* src, size_t sz)
{
	char* cpSrc = (char*)src;
	char* cpDst = (char*)dest;

	for (int i = 0; i < sz; i++)
		cpDst[i] = cpSrc[i];

	return dest;
}