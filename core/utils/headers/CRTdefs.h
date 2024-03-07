#pragma once
#include <Windows.h>
#include <stddef.h>



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
int atexit(void (*function)(void)) {
	// Check if there is space in the array
	if (num_atexit_funcs < MAX_ATEXIT_FUNCS) {
		// Add the function to the array
		atexit_funcs[num_atexit_funcs++].func = function;
		return 0; // Success
	}
	else {
		return 1; // Failure, array is full
	}
}

// Function to call all registered functions on program exit
void call_atexit_funcs() {
	// Call each registered function in reverse order
	for (size_t i = num_atexit_funcs; i > 0; --i) {
		atexit_funcs[i - 1].func();
	}
}


size_t __cdecl strlen(const char* str)
{
	// I think this is an awful implementation
	//for (int i = 0; i < sizeof(str); i++)
	//{
	//	if (str[i] == '\0')
	//		return i;
	//}

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

//INT StringCompareW(_In_ LPCWSTR String1, _In_ LPCWSTR String2)
//{
//	for (; *String1 == *String2; String1++, String2++)
//	{
//		if (*String1 == '\0')
//			return 0;
//	}
//
//	return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
//}

void* __cdecl memset(void* dest, int val, size_t sz) {
	// logic similar to memset's one
	unsigned char* p = (unsigned char*)dest;
	while (sz > 0) {
		*p = (unsigned char)val;
		p++;
		sz--;
	}
	return dest;
}

void __cdecl memcpy(void*& dest, void*& src, size_t sz)
{
	char* cpSrc = (char*)src;
	char* cpDst = (char*)dest;

	for (int i = 0; i < sz; i++)
		cpDst[i] = cpSrc[i];
}


#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  


