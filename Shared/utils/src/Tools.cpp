#include "../headers/Tools.h"
#include <functional>

void Logging::ShowError(const char* error)
{
//#ifdef _DEBUG
    MessageBoxA(NULL, error, "Error", MB_ICONERROR | MB_OK);
//#endif // DEBUG
}

void Logging::ShowError(const char* error, int errnum)
{
    //#ifdef _DEBUG
        // Format the error message with the error number
    std::string errorMessage = std::string(error) + " " + std::to_string(errnum);

    // Display the error message using MessageBoxA
    MessageBoxA(NULL, errorMessage.c_str(), "Error", MB_ICONERROR | MB_OK);
    //#endif // DEBUG
}
void Logging::DisplayMessage(const char *format, ...)
{
    const int bufferSize = 512;
    char buffer[bufferSize];

    va_list args;
    va_start(args, format);
    vsnprintf(buffer, bufferSize, format, args);
    va_end(args);

    MessageBoxA(NULL, buffer, "Debug", MB_ICONINFORMATION | MB_OK);
}

void Logging::EnableDebugConsole()
{
    if (AllocConsole())
    {
        FILE* fpStdout = stdout;
        FILE* fpStdin  = stdin;

        freopen_s(&fpStdout, "CONOUT$", "w", stdout);
        freopen_s(&fpStdin, "CONOUT$", "w", stdin);
        SetWindowText(GetConsoleWindow(), "Debug Console");

    }
}
