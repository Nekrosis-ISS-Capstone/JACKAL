#pragma once
#include <Windows.h>
#include <stddef.h>

#define MemCopy         __movsb                                                // Replacing memcpy
#define MemSet          __stosb                                                // Replacing memset
#define MemZero( p, l ) __stosb( ( char* ) ( ( PVOID ) p ), 0, l )             // Replacing ZeroMemory   

#define C_PTR( x )      ( PVOID )     ( x )         // Type-cast to PVOID
#define U_PTR( x )      ( ULONG_PTR ) ( x )         // Type-cast to ULONG_PTR

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

#pragma intrinsic(atexit)
#pragma function (atexit)


// Define a maximum number of functions to register with atexit
#define MAX_ATEXIT_FUNCS 32

// Define a structure to hold the registered functions
struct AtExitFunc {
	void (*func)(void);
};

// Define an array to hold the registered functions
static struct AtExitFunc atexit_funcs[MAX_ATEXIT_FUNCS];
static size_t num_atexit_funcs = 0;

// Implementation of the atexit function
int atexit(void (*function)(void));
// Function to call all registered functions on program exit
void call_atexit_funcs();

size_t __cdecl strlen(const char* str);

int __cdecl strcmp(_In_ LPCSTR String1, _In_ LPCSTR String2);

void* __cdecl memset(void* dest, int val, size_t sz);

void* __cdecl memcpy(void* dest, const void* src, size_t sz);