#include <Windows.h>
#include "common.h"
#include "LOG.h"

static BOOL WINAPI _wipeFileContent(HANDLE hFile)
{
	const char zero[512] = {};

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	DWORD file_size = FNC(GetFileSize)(hFile, NULL);

	if (file_size == INVALID_FILE_SIZE)
		file_size = 0;

	DWORD dwTmp = 0;

	while (file_size > 0) {
		dwTmp = (file_size > sizeof(zero)) ? sizeof(zero) : file_size;
		FNC(WriteFile)(hFile, &zero, sizeof(zero), &dwTmp, NULL);
		file_size -= dwTmp;
	}
	
	return TRUE;
}

// Tenta a tutti i costi di cancellare un file
void HM_WipeFileA(LPCSTR lpFileName)
{
	BOOL ret_val = FALSE;
	DWORD i;

	// Toglie il readonly
	for (i = 0; i < MAX_DELETE_TRY; i++) {
		ret_val = FNC(SetFileAttributesA)(lpFileName, FILE_ATTRIBUTE_NORMAL);
		if (ret_val || GetLastError() == ERROR_FILE_NOT_FOUND)
			break;
		Sleep(DELETE_SLEEP_TIME);
	}

	// Sovrascrive (solo se e' stato configurato per farlo)
	if (log_wipe_file) {
		for (i = 0; i < MAX_DELETE_TRY; i++) {
			HANDLE hFile = FNC(CreateFileA)(lpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			if (_wipeFileContent(hFile)) {
				CloseHandle(hFile);
				break;
			}
			Sleep(DELETE_SLEEP_TIME);
		}
	}

	// Cancella
	for (i = 0; i < MAX_DELETE_TRY; i++) {
		ret_val = FNC(DeleteFileA)(lpFileName);
		if (ret_val || GetLastError() == ERROR_FILE_NOT_FOUND)
			break;
		Sleep(DELETE_SLEEP_TIME);
	}
}


void HM_WipeFileW(LPCWSTR lpFileName)
{
	DWORD i;
	HANDLE hFile = NULL;

	// Toglie il readonly
	for (i = 0; i < MAX_DELETE_TRY; i++) {
		if (FNC(SetFileAttributesW)(lpFileName, FILE_ATTRIBUTE_NORMAL))
			break;
		Sleep(DELETE_SLEEP_TIME);
	}

	// Sovrascrive (solo se e' stato configurato per farlo)
	if (log_wipe_file) {
		for (i = 0; i < MAX_DELETE_TRY; i++) {
			if ((hFile = FNC(CreateFileW)(lpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) {
				if (_wipeFileContent(hFile))
					CloseHandle(hFile);
				break;
			}
			Sleep(DELETE_SLEEP_TIME);
		}
	}

	// Cancella
	for (i = 0; i < MAX_DELETE_TRY; i++) {
		if (FNC(DeleteFileW)(lpFileName))
			break;
		Sleep(DELETE_SLEEP_TIME);
	}
}
