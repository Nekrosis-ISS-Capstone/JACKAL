#include "../dll/source/headers/HookIAT.h"
#include "utils/headers/Tools.h"

void* HookIAT(PBYTE pTarget, PCSTR lpModuleName, PCSTR lpApiName, void* pReplacement)
{
	//Tools tools;
	
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pTarget;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		/*tools.ShowError("Incorrect File type");*/
		return 0;
	}

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pTarget + pImgDosHdr->e_lfanew); // e_lfanew points to the NT header
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
	{
		//tools.ShowError("NT Signature not matching");
		return 0;
	}
	return nullptr;
}
