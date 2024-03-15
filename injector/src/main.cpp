#include "Windows.h"
#include <API/headers/api.h>
#include "utils/headers/antianalysis.h"

import MyModule;


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	AntiAnalysis debug;
	//int x = MyFunc(1);

	//auto resolved = UseResolver();

	auto& resolver = API::APIResolver::GetInstance();
	auto resolved	  = resolver.GetAPIAccess();

	resolver.IATCamo();
	resolver.LoadModules();
	resolver.ResolveFunctions();


	auto& resolver = API::APIResolver::GetInstance();
	debug.PebCheck(resolver);

	if(!resolved.func.pNtCreateProcess)
		MessageBoxA(NULL, "not working", "working", NULL);



	return 0;
} 