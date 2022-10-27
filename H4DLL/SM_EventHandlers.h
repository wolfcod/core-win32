#include <stdio.h>
// Ogni Event Monitor ha tre funzioni, una per start, una per stop
// e una per istruire una nuova condizione da monitorare

// Definita dentro SM_Core.cpp, di cui questo file e' un include
void TriggerEvent(DWORD, DWORD);

//---------------------------------------------------

#define PR_WINDOW_MASK 1
#define PR_FOREGROUND_MASK 2
typedef struct {
	WCHAR *proc_name;
	DWORD isWindow;
	DWORD isForeground;
	BOOL present;
	EVENT_PARAM event_param;
	DWORD event_id;
} monitored_proc;

typedef struct {
	DWORD index;
	BOOL found;
} enum_win_par_struct;

// screensaver
void WINAPI EM_ScreenSaverAdd(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_ScreenSaverStart();
void WINAPI EM_ScreenSaverStop();

// process monitor
void WINAPI EM_MonProcAdd(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_MonProcStart();
void WINAPI EM_MonProcStop();

// connection events
void WINAPI EM_MonConnAdd(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_MonConnStart();
void WINAPI EM_MonConnStop();

// user idle events
void WINAPI EM_UserIdlesAdd(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_UserIdlesStart();
void WINAPI EM_UserIdlesStop();

// event log events
void WINAPI EM_MonEventAdd(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_MonEventStart();
void WINAPI EM_MonEventStop();


// Quota events
void WINAPI EM_QuotaStart();
void WINAPI EM_QuotaStop();
void WINAPI EM_QuotaAdd(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id);

// Windows events
void WINAPI EM_NewWindowAdd(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_NewWindowStart();
void WINAPI EM_NewWindowStop();

// Timer events
void WINAPI EM_TimerAdd(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_TimerStart();
void WINAPI EM_TimerStop();
