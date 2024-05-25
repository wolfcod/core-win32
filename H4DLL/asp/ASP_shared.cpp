#include <Windows.h>
#include "../common.h"
#include "../H4-DLL.h"
#include "../AM_Core.h"
#include "ASP.h"

HANDLE ASP_HostProcess = NULL; // Processo che gestisce ASP
ASP_IPC_CTRL* ASP_IPC_command = NULL;  // Area di shared memory per dare comandi al processo ASP
HANDLE hASP_CmdFile = NULL;                  // File handle della shared memory dei comandi
CONNECTION_HIDE connection_hide = NULL_CONNETCION_HIDE_STRUCT; // struttura per memorizzare il pid da nascondere
PID_HIDE pid_hide = NULL_PID_HIDE_STRUCT; // struttura per memorizzare la connessione da nascondere
HINTERNET asp_global_request = 0; // Handle usato dalle winhttp per inviare/ricevere dati

// De-pascalizza la stringa (alloca la stringa)
WCHAR* UnPascalizeString(BYTE* data, DWORD* retlen)
{
	*retlen = *((DWORD*)data);
	data += sizeof(DWORD);

	return wcsdup((WCHAR*)data);
}

// Ritorna la stringa pascalizzata
// il buffer ritornato va liberato
BYTE* PascalizeString(WCHAR* string, DWORD* retlen)
{
	DWORD len;
	BYTE* buffer;

	len = (wcslen(string) + 1) * sizeof(WCHAR);
	buffer = (BYTE*)malloc(len + sizeof(DWORD));
	if (!buffer)
		return NULL;
	ZeroMemory(buffer, len + sizeof(DWORD));
	memcpy(buffer, &len, sizeof(DWORD));
	wcscpy_s((WCHAR*)(buffer + sizeof(DWORD)), len / sizeof(WCHAR), string);

	*retlen = len + sizeof(DWORD);
	return buffer;
}
