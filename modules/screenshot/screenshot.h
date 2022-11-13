#pragma once

HWND __stdcall PM_CreateWindowEx(DWORD dwExStyle,
	LPCTSTR lpClassName,
	LPCTSTR lpWindowName,
	DWORD dwStyle,
	int x,
	int y,
	int nWidth,
	int nHeight,
	HWND hWndParent,
	HMENU hMenu,
	HINSTANCE hInstance,
	LPVOID lpParam);

DWORD PM_CreateWindowEx_setup(HMServiceStruct* pData);

// Hook per la notifica di creazione di nuove finestre
typedef struct {
	COMMONDATA;
} CreateWindowExStruct;

extern CreateWindowExStruct CreateWindowExData;
