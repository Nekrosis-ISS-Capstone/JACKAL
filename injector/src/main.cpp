#include "Windows.h"
#include "../API/headers/api.h"

import MyModule;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	int x = MyFunc(1);



	MessageBox(NULL, (const char*)x, "asdasd", NULL);


	//API::APIResolver resolver;
	//MessageBoxA(NULL, "test", "h", NULL);
} 