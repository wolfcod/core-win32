#include <windows.h>
#include <stdint.h>
#include "sha256.h"
#include "../md5.h"

static const char ascii[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd' ,'e', 'f' };

#define char2hex(dst, src) *dst++ = ascii[(src & 0xf0) >> 4]; *dst++ = ascii[(src & 0x0f)]

union word {
	uint16_t value;
	struct {
		uint8_t lower;
		uint8_t higher;
	};
};

void hex2ascii(char *dst, const uint8_t *src, size_t size)
{
	if (dst != NULL && src != NULL) {
		while (size-- > 0)
		{
			char2hex(dst, *src);
			*src++;
		}

		*dst = 0x00;
	}
}

void hex2ascii(char *dst, uint16_t *src, size_t size)
{
	if (dst == NULL || src == NULL)
		return;

	while(size-- > 0) {
		word c; c.value = *src;
		
		if (c.higher != 0) {
			char2hex(dst, c.higher);
		}
		char2hex(dst, c.lower);

		src++;
	}

	*dst= 0x00;
}

///////////////////////////////////////////////////////////////////////////////
// SHA256 of file
//	Input:
//		lpFileName	: full path of plugin
//	Output:
//		sha256		: SHA256 in plain-text (lower case)
//
BOOL SHA256_Array(char *lpOutChecksum, void *array, int size)
{
	SHA256Context context;

	Sha256_Init(&context);

	Sha256_Update(&context, (byte *) array, (size_t) size);

	unsigned char sha256_digest[32];

	Sha256_Final(&context, sha256_digest);

	hex2ascii(lpOutChecksum, (uint8_t *) sha256_digest, sizeof(sha256_digest));

	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////
// MD5 of file
//	Input:
//		lpFileName	: full path of plugin
//	Output:
//		sha256		: SHA256 in plain-text (lower case)
//
BOOL MD5_Plugin(char *lpFileName, char *lpOutChecksum)
{
	if (lpFileName == NULL || lpOutChecksum == NULL)
		return FALSE;


	HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	MD5_CTX context;

	MD5Init(&context);

	void *buffer = malloc(64000);
	if (buffer == NULL)
		return FALSE;
	DWORD dwBytesRead = 0;

	while(ReadFile(hFile, buffer, 64000, &dwBytesRead, NULL) == TRUE)
	{
		if (dwBytesRead == 0)	// end of file?
			break;

		MD5Update(&context, (byte *) buffer, (size_t) dwBytesRead);
	}

	CloseHandle(hFile);
	free(buffer);


	MD5Final(&context);
	hex2ascii(lpOutChecksum, (uint8_t *) context.digest, sizeof(context.digest));

	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////
// MD5 of file
//	Input:
//		lpFileName	: full path of plugin
//	Output:
//		sha256		: md5 in plain-text (lower case)
//
BOOL MD5_Array(char *lpOutChecksum, char *array, int size)
{
	MD5_CTX context;

	MD5Init(&context);

	MD5Update(&context, (byte *) array, (size_t) size);

	MD5Final(&context);
	hex2ascii(lpOutChecksum, (uint8_t *) context.digest, sizeof(context.digest));

	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////
// SHA256 of file
//	Input:
//		lpFileName	: full path of plugin
//	Output:
//		sha256		: SHA256 in plain-text (lower case)
//
BOOL SHA256_Plugin(char *lpFileName, char *lpOutChecksum, BOOL isOld)
{
	if (lpFileName == NULL || lpOutChecksum == NULL)
		return FALSE;


	HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	SHA256Context context;

	Sha256_Init(&context);

	void *buffer = malloc(64000);

	DWORD dwBytesRead = 0;

	while(ReadFile(hFile, buffer, 64000, &dwBytesRead, NULL) == TRUE)
	{
		if (dwBytesRead == 0)	// end of file?
			break;

		Sha256_Update(&context, (byte *) buffer, (size_t) dwBytesRead);
	}

	CloseHandle(hFile);
	free(buffer);

	unsigned char sha256_digest[32];

	Sha256_Final(&context, sha256_digest);

	wchar_t unicodesha[32];
	if (isOld) {
		MultiByteToWideChar(CP_ACP, 0, (LPCSTR) sha256_digest, sizeof(sha256_digest), unicodesha, 32);
		hex2ascii(lpOutChecksum, (uint16_t *) unicodesha, 32);
	} else {
		hex2ascii(lpOutChecksum, (uint8_t *)sha256_digest, 32);
	}
	return TRUE;
}

