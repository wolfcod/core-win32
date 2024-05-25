void SM_StartMonitorEvents(void);
void SM_EventTableState(DWORD event_id, BOOL state);
void CreateRepeatThread(DWORD event_id, DWORD repeat_action, DWORD count, DWORD delay);
void StopRepeatThread(DWORD event_id);


typedef struct {
	DWORD start_action;
	DWORD stop_action;
	DWORD repeat_action;
	DWORD count;
	DWORD delay;
} EVENT_PARAM;