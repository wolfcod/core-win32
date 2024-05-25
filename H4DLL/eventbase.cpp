#include <Windows.h>
#include <json/JSON.h>
#include "common.h"
#include "SM_Core.h"
#include "SM_EventHandlers.h"

#define DEFAULT_SLEEP_TIME 3000

EventMonitorBase::EventMonitorBase()
	: hWorkerThread(NULL), bSemaphore(FALSE), dwThreadId(0), wakeUpTime(DEFAULT_SLEEP_TIME)
{

}

EventMonitorBase::~EventMonitorBase()
{
}

void EventMonitorBase::start()
{
	onStart();

	if (hWorkerThread == NULL)
	{
		hWorkerThread = CreateThread(NULL, 0, &EventMonitorBase::EventMonitorBaseThread, (LPVOID)this, 0, &dwThreadId);
	}
}

void EventMonitorBase::stop()
{
	if (hWorkerThread != NULL)
	{
		QUERY_CANCELLATION(hWorkerThread, bSemaphore);
	}

	onStop();
}

void EventMonitorBase::add(JSONObject conf_json, EVENT_PARAM* event_param, DWORD event_id)
{
	onAdd(conf_json, event_param, event_id);
}

DWORD WINAPI EventMonitorBase::EventMonitorBaseThread(LPVOID lpParameter)
{
	EventMonitorBase* base = reinterpret_cast<EventMonitorBase*>(lpParameter);

	if (base != nullptr) {

		LOOP{
			CANCELLATION_POINT(base->bSemaphore);
			base->onRun();
			Sleep(base->wakeUpTime);
		}
	}

	return 0;
}
