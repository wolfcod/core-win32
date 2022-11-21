#include "exceptions.h"
#include <Sddl.h>

// La memoria per la lettura e' composta da una serie di strutture che il server scrive e tutti i client
// possono leggere. La memoria per la scrittura implementa una coda di messaggi in cui i client scrivono
// e da cui il server legge.
// I client scrivono IPC_MESSAGE e leggono BYTE che poi loro casteranno.

// Valori base (modificabili a seconda delle esigenze)
#define MAX_MSG_LEN 0x400 // Lunghezza di un messaggio
#define MAX_MSG_NUM 3000 // Massimo numero di messaggi in coda
#define SHARE_MEMORY_READ_SIZE (WRAPPER_COUNT*WRAPPER_MAX_SHARED_MEM) // Dimensione spazio per la lettura delle configurazioni da parte dei wrapper                                

// Valori derivati
#define SHARE_MEMORY_WRITE_SIZE ((MAX_MSG_NUM * sizeof(IPC_MESSAGE))+2)


// Macro di supporto
#define DATA_SUPPORT DWORD dwFuncLen; DWORD dwFuncAdd; DWORD dwDataAdd;
typedef struct { DATA_SUPPORT; } Generic_data_support;
#define INIT_SFUNC(STRTYPE)			STRTYPE *pData; \
									__asm    MOV EBX,69696969h \
									__asm	 MOV DWORD PTR SS:[pData], EBX \

#define MMCPY(DST, SRC, SIZ)		{ BYTE *lsrc = (BYTE *)SRC; \
									  BYTE *ldst = (BYTE *)DST; \
									  DWORD lsiz = (DWORD)SIZ; \
									__asm MOV ESI, lsrc \
									__asm MOV EDI, ldst \
									__asm MOV ECX, lsiz \
									__asm REP MOVSB }


#define STATUS_FREE 0 << 4	// available
#define STATUS_BUSY 1 << 4	// taken
#define STATUS_WRIT 2 << 4	// wrote

#define IPC_LOW_PRIORITY 0x0
#define IPC_DEF_PRIORITY 0x1
#define IPC_HI_PRIORITY  0x2

// Struttura di un messaggio scritto dai client
// Il corpo del messaggio DEVE essere sempre l'ultimo elemento (vedi IPCServerRead)
// XXX Se modifico va cabiato anche in AM_Core
typedef struct {
	BYTE state;
	FILETIME time_stamp;
	DWORD wrapper_tag;
	DWORD message_len;
	DWORD flags;
	BYTE message[MAX_MSG_LEN];
} IPC_MESSAGE;

#define GET_PRIORITY(ipc) (ipc->state & 0x02)
#define SET_PRIORITY(ipc, priority) ipc->state = (ipc->state & 0xfc) | priority
#define GET_STATUS(ipc) (ipc->state >> 4)
#define SET_STATUS(ipc, status) ipc->state = ipc->state & 0x02 | status

extern BOOL IsVista(DWORD *integrity_level);
void *FindTokenObject(HANDLE Handle);

extern void* IPC_SHM_Kernel_Object;

//-------------------- FUNZIONI DA INIETTARE (Client) ----------------------
//////////////////////////
//						//
//    IPCClientRead     //
//						//
//////////////////////////
typedef struct {
	COMMONDATA;
	BYTE *mem_addr;
} IPC_CLIENT_READ;

// Ritorna l'indirizzo di memoria della configurazione di un dato wrapper
// Torna NULL se fallisce
BYTE* WINAPI IPCClientRead(DWORD wrapper_tag);
DWORD IPCClientRead_setup(DWORD dummy);

//////////////////////////
//						//
//    IPCClientWrite    //
//						//
//////////////////////////
typedef void (WINAPI *GetSystemTimeAsFileTime_t) (LPFILETIME);
typedef struct {
	COMMONDATA;
	IPC_MESSAGE *mem_addr;
	GetSystemTimeAsFileTime_t pGetSystemTimeAsFileTime;
	DWORD increment;
	DWORD old_low_part;
	DWORD old_hi_part;
} IPC_CLIENT_WRITE;

extern IPC_CLIENT_READ ipc_read;
extern IPC_CLIENT_WRITE ipc_write;

// Torna TRUE se ha scritto, FALSE se fallisce
BOOL WINAPI IPCClientWrite(DWORD wrapper_tag, BYTE* message, DWORD msg_len, DWORD flags, DWORD priority);
DWORD IPCClientWrite_setup(DWORD dummy);
void IPCServerWrite(DWORD wrapper_tag, BYTE* buff, DWORD size);

// Ritorna TRUE se tm1 e' piu' vecchio di tm2
BOOL is_older(FILETIME* tm1, FILETIME* tm2);

// Piu' veloce della Read, ritorna direttamente il messaggio nella shared memory (non fa la memcpy)
// Ma necessita che poi il messaggio sia rimosso a mano dopo che e' stato completato il dispatch
// Garantiesce l'ordinamento
IPC_MESSAGE* IPCServerPeek();

// Rimuove dalla coda un messaggio preso con IPCServerPeek
void IPCServerRemove(IPC_MESSAGE* msg);
// Se la shared memory gia' esiste ritorna FALSE
BOOL IPCServerInit();
