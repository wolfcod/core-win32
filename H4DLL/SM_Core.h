#ifndef __SMCORE_H
#define __SMCORE_H

typedef struct event_param 
{
	DWORD start_action;
	DWORD stop_action;
	DWORD repeat_action;
	DWORD count;
	DWORD delay;
} EVENT_PARAM;

void SM_StartMonitorEvents(void);
void SM_EventTableState(DWORD event_id, BOOL state);

/** schedule a Repeat Thread for a specific event, according to parameters provided in EVENT_PARAM (received in configuration) */
void CreateRepeatThread(DWORD event_id, EVENT_PARAM* param);

void StopRepeatThread(DWORD event_id);

#endif
