#pragma once
#ifndef CRTDEFS_H
#define CRTDEFS_H

#include <Windows.h>
#include <stddef.h>

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()  ((HANDLE)-2)


//extern void* __cdecl memset(void*, int, size_t);

// Force compiler to use our versions of crt functions
#pragma intrinsic(memset)
#pragma function (memset)

#pragma intrinsic(memcpy)
#pragma function (memcpy)

#pragma intrinsic(strcmp)
#pragma function (strcmp)

#pragma intrinsic(strlen)
#pragma function (strlen)

//#pragma intrinsic(atexit)
//#pragma function (atexit)


// Define a maximum number of functions to register with atexit
#define MAX_ATEXIT_FUNCS 32

// Define a structure to hold the registered functions
struct AtExitFunc {
	void (*func)(void);
};

// Define an array to hold the registered functions
static struct AtExitFunc AtExitFuncs[MAX_ATEXIT_FUNCS];
static size_t sAtExitFuncs = 0;

// Implementation of the atexit function
int atexit(void (*function)(void));
// Function to call all registered functions on program exit
void call_atexit_funcs();

size_t __cdecl strlen(const char* str);

int __cdecl strcmp(_In_ LPCSTR String1, _In_ LPCSTR String2);

void* __cdecl memset(void* dest, int val, size_t sz);

void* __cdecl memcpy(void* dest, const void* src, size_t sz);


#endif // !CRTDEFS_H