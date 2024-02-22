#include "../headers/Tools.h"
#include <functional>
#include <iostream>

void Logging::ShowError(const char* error)
{
#ifdef _DEBUG
    MessageBoxA(NULL, error, "Error", MB_ICONERROR | MB_OK);
#endif // DEBUG
}

void Logging::ShowError(const char* error, int errnum)
{
    #ifdef _DEBUG
        // Format the error message with the error number
    std::string errorMessage = std::string(error) + " " + std::to_string(errnum);

    // Display the error message using MessageBoxA
    MessageBoxA(NULL, errorMessage.c_str(), "Error", MB_ICONERROR | MB_OK);
    #endif // DEBUG
}
void Logging::DisplayMessage(const char *format, ...)
{
#ifdef _DEBUG
    const int bufferSize = 512;
    char buffer[bufferSize];

    va_list args;
    va_start(args, format);
    vsnprintf(buffer, bufferSize, format, args);
    va_end(args);

    MessageBoxA(NULL, buffer, "Debug", MB_ICONINFORMATION | MB_OK);
#endif
}

void Logging::EnableDebugConsole()
{
#ifdef _DEBUG
    if (AllocConsole())
    {
        FILE* fpStdout = stdout;
        FILE* fpStdin  = stdin;

        freopen_s(&fpStdout, "CONOUT$", "w", stdout);
        freopen_s(&fpStdin, "CONOUT$", "w", stdin);
        SetWindowText(GetConsoleWindow(), "Debug Console");

    }
#endif
}

void Logging::PrintConsole(std::string message)
{
    std::cout << message << "\n";
}



void* __cdecl CRT::_memset(void* dst, int value, size_t size)
{
    unsigned char* p = (unsigned char*)dst;

    while (size > 0)
    {
        *p = (unsigned char)value;
        p++;
        size--;
    }
    return dst;
}

void CRT::_memcpy(void* dest, void* src, size_t sz)
{
    char* cpSrc = (char*)src;
    char* cpDst = (char*)dest;

    for (int i = 0; i < sz; i++)
        cpDst[i] = cpSrc[i];
}
