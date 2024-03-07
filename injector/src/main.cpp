#include "Windows.h"
#include <API/headers/api.h>
#include "utils/headers/antianalysis.h"

//import MyModule;


class Singleton
{
public:
	Singleton(const Singleton&) = delete;

	static Singleton& GetInstance()
	{
		/*static Singleton instance;*/
		return instance;
	}
	void func() {};

private:
	Singleton() {}
	

	static Singleton instance;


};
Singleton Singleton::instance;


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	//int x = MyFunc(1);

	//auto& singleton = Singleton::GetInstance();

	//singleton.func();

	auto& resolver = API::APIResolver::GetInstance();
	//resolver.IATCamo();
	//resolver.LoadModules();
	//resolver.ResolveFunctions();

	auto resolved    = resolver.GetAPIAccess();

	AntiAnalysis debug;

	debug.PebCheck(resolver);

	if(!resolved.func.pNtCreateProcess)
		MessageBoxA(NULL, "not working", "working", NULL);



	return 0;
} 