#pragma once
#ifndef ENCRYPT_PAYLOAD_H
#define ENCRYPT_PAYLOAD_H

#define KEYSIZE		32
#define IVSIZE		16

#define WIN32_LEAN_AND_MEAN
#include <API/headers/api.h>
#include <utils/headers/Tools.h>


extern unsigned char payload[];

typedef struct _AES {

	PBYTE	pPlainText;				// Base address of the plaintext data 
	DWORD	dwPlainSize;			// Size of the plaintext data

	PBYTE	pCipherText;			// Base address of the encrypted data	
	DWORD	dwCipherSize;			// Size of the encrypted data. This can vary from dwPlainSize when there is padding involved.

	PBYTE	pKey;					// The 32 byte key
	PBYTE	pIv;					// The 16 byte IV

}AES, * PAES;



class Encrypt
{
	bool CleanEncrypt(void*& hKeyHandle, void*& hAlgorithm, unsigned char*& pbKeyObject, PAES& pAes, unsigned char *pbCiperText, DWORD cbCiperText, API::API_ACCESS& api);
	bool InstallAes(PAES pAes, API::API_ACCESS& api);

public:
	bool SimpleEncryption(_In_ void *pPlainTextData, _In_ DWORD sPlainTextSize, _In_ unsigned char *pKey, _In_ unsigned char *pIv, _In_ void** ppCipherTextData, _Out_ DWORD* sCipherTextSize, API::API_ACCESS& api);

};


#endif