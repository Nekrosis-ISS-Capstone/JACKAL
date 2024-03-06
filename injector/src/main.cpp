#include "Windows.h"
#include <API/headers/api.h>
#include "utils/headers/antianalysis.h"

//import MyModule;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	//int x = MyFunc(1);

	API::APIResolver resolver;

	AntiAnalysis debug;

	debug.PebCheck(resolver);

	
} 