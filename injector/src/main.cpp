#include "Windows.h"
#include <API/headers/api.h>
#include "utils/headers/antianalysis.h"

import MyModule;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	//int x = MyFunc(1);

	auto resolved = UseResolver();

	AntiAnalysis debug;
	auto& resolver = API::APIResolver::GetInstance();
	debug.PebCheck(resolver);

	if(!resolved.func.pNtCreateProcess)
		MessageBoxA(NULL, "not working", "working", NULL);



	return 0;
} 