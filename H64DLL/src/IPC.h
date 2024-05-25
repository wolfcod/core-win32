#define WRAPPER_MAX_SHARED_MEM 0x40

#define MAX_MSG_LEN 0x400 // Lunghezza di un messaggio
#define MAX_MSG_NUM 3000 // Massimo numero di messaggi in coda

typedef struct {
	BYTE status; 
#define STATUS_FREE 0 // Libero
#define STATUS_BUSY 1 // In scrittura
#define STATUS_WRIT 2 // Scritto
	FILETIME time_stamp;
	DWORD wrapper_tag;
	DWORD message_len;
	DWORD flags;
	DWORD priority;
#define IPC_LOW_PRIORITY 0x0
#define IPC_DEF_PRIORITY 0x10
#define IPC_HI_PRIORITY  0x100
	BYTE message[MAX_MSG_LEN];
} IPC_MESSAGE;

typedef struct {
	BYTE *mem_addr;
} IPC_CLIENT_READ;

typedef void (WINAPI *GetSystemTimeAsFileTime_t) (LPFILETIME);
typedef struct {
	IPC_MESSAGE *mem_addr;
	GetSystemTimeAsFileTime_t pGetSystemTimeAsFileTime;
	DWORD increment;
	DWORD old_low_part;
	DWORD old_hi_part;
} IPC_CLIENT_WRITE;

typedef BOOL (WINAPI *IPCClientWrite_t)(DWORD wrapper_tag, IPC_CLIENT_WRITE *pData, BYTE *message, DWORD msg_len, DWORD flags, DWORD priority);
typedef BYTE *(WINAPI *IPCClientRead_t)(DWORD wrapper_tag, IPC_CLIENT_READ *pData);

extern void IPCClientWrite_setup(IPC_CLIENT_WRITE *data);
extern void IPCClientRead_setup(IPC_CLIENT_READ *data);
extern BOOL WINAPI IPCClientWrite(DWORD wrapper_tag, IPC_CLIENT_WRITE *pData, BYTE *message, DWORD msg_len, DWORD flags, DWORD priority);
extern BYTE * WINAPI IPCClientRead(DWORD wrapper_tag, IPC_CLIENT_READ *pData);

#define SHARE_MEMORY_WRITE_SIZE ((MAX_MSG_NUM * sizeof(IPC_MESSAGE))+2)
#define SHARE_MEMORY_READ_SIZE (WRAPPER_COUNT*WRAPPER_MAX_SHARED_MEM) // Dimensione spazio per la lettura delle configurazioni da parte dei wrapper                                
//#define SHARE_MEMORY_READ_BASENAME "DPA"
//#define SHARE_MEMORY_WRITE_BASENAME "DPB"

extern char SHARE_MEMORY_READ_NAME[];
extern char SHARE_MEMORY_WRITE_NAME[];

#define COMMON_IPC_DATA BOOL active;

typedef struct {
	COMMON_IPC_DATA;
} common_ipc_conf_struct;

#define IPC_CLIENT_READ(TAG) if (pData->ipc_client_read) {pData->ipc_client_read(TAG, pData->ipc_read_data);}
#define IPC_CLIENT_WRITE(TAG, MSG, MSGLEN, FLAGS, PRIORITY) if (pData->ipc_client_write) {pData->ipc_client_write(TAG, pData->ipc_write_data, MSG, MSGLEN, FLAGS, PRIORITY);} 

#define IF_ACTIVE_AGENT(TAG) if(pData->ipc_client_read && (common_ipc_conf=(common_ipc_conf_struct *)pData->ipc_client_read(TAG, pData->ipc_read_data)) && common_ipc_conf->active ) 