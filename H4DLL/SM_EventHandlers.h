#include <stdio.h>
#include <cJSON/cJSON.h>
// Ogni Event Monitor ha tre funzioni, una per start, una per stop
// e una per istruire una nuova condizione da monitorare

// Definita dentro SM_Core.cpp, di cui questo file e' un include
void TriggerEvent(DWORD, DWORD);

class EventMonitorBase
{
public:
	EventMonitorBase();
	~EventMonitorBase();

	void start();
	void stop();
	void add(cJSON* conf_json, EVENT_PARAM* event_param, DWORD event_id);

protected:
	virtual void onStart() = 0;
	virtual void onRun() = 0;
	virtual void onStop() = 0;
	virtual void onAdd(cJSON* json, EVENT_PARAM* event_param, DWORD event_id) = 0;

private:
	HANDLE	hWorkerThread;
	BOOL	bSemaphore;
	DWORD	dwThreadId;
	DWORD	wakeUpTime;
	static DWORD WINAPI EventMonitorBaseThread(LPVOID lpParameter);
};

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
void WINAPI EM_ScreenSaverAdd(cJSON* conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_ScreenSaverStart();
void WINAPI EM_ScreenSaverStop();

// process monitor
void WINAPI EM_MonProcAdd(cJSON* conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_MonProcStart();
void WINAPI EM_MonProcStop();

// connection events
void WINAPI EM_MonConnAdd(cJSON* conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_MonConnStart();
void WINAPI EM_MonConnStop();

// user idle events
void WINAPI EM_UserIdlesAdd(cJSON* conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_UserIdlesStart();
void WINAPI EM_UserIdlesStop();

// event log events
void WINAPI EM_MonEventAdd(cJSON* conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_MonEventStart();
void WINAPI EM_MonEventStop();

class EventMonitorLog :
	public EventMonitorBase
{
public:
	void onStart() override;
	void onRun() override;
	void onStop() override;
	void onAdd(cJSON* json, EVENT_PARAM* event_param, DWORD event_id) override;
};


// Quota events
void WINAPI EM_QuotaStart();
void WINAPI EM_QuotaStop();
void WINAPI EM_QuotaAdd(cJSON* conf_json, EVENT_PARAM* event_param, DWORD event_id);

// Windows events
void WINAPI EM_NewWindowAdd(cJSON* conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_NewWindowStart();
void WINAPI EM_NewWindowStop();

// Timer events
void WINAPI EM_TimerAdd(cJSON* conf_json, EVENT_PARAM* event_param, DWORD event_id);
void WINAPI EM_TimerStart();
void WINAPI EM_TimerStop();
