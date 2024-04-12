#include <utils/headers/tools.h>
#include <functional>
#include <iostream>

void Tools::ShowError(const char* error)
{
#ifdef _DEBUG
    MessageBoxA(NULL, error, "Error", MB_ICONERROR | MB_OK);
#endif // DEBUG
}

//void Logging::ShowError(const char* error, int errnum)
//{
//#ifdef _DEBUG
//     Format the error message with the error number
//    std::string errorMessage = std::string(error) + " " + std::to_string(errnum);
//
//     Display the error message using MessageBoxA
//    MessageBoxA(NULL, errorMessage.c_str(), "Error", MB_ICONERROR | MB_OK);
//#endif // DEBUG
//}
//void Logging::DisplayMessage(const char* format, ...)
//{
//#ifdef _DEBUG
//    const int bufferSize = 512;
//    char buffer[bufferSize];
//
//    va_list args;
//    va_start(args, format);
//    vsnprintf(buffer, bufferSize, format, args);
//    va_end(args);
//
//    MessageBoxA(NULL, buffer, "Debug", MB_ICONINFORMATION | MB_OK);
//#endif
//}
//
//
//void Logging::PrintConsole(std::string message)
//{
//    std::cout << message << "\n";
//}
//

void Tools::ExitProgram(const char* message)
{
    MessageBoxA(NULL, message, "error", MB_ICONWARNING);
    ExitProcess(-1);
}


void Tools::EnableDebugConsole() {
#ifdef _DEBUG
    if (AllocConsole()) {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);

        if (hOut != INVALID_HANDLE_VALUE && hIn != INVALID_HANDLE_VALUE) {
            SetConsoleTitle("Debug Console");
            SetStdHandle(STD_OUTPUT_HANDLE, hOut);
            SetStdHandle(STD_INPUT_HANDLE, hIn);
        }
    }
#endif
}
