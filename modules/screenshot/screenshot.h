#pragma once

HWND WINAPI PM_CreateWindowEx(DWORD dwExStyle,
	LPCSTR lpClassName,
	LPCSTR lpWindowName,
	DWORD dwStyle,
	int x,
	int y,
	int nWidth,
	int nHeight,
	HWND hWndParent,
	HMENU hMenu,
	HINSTANCE hInstance,
	LPVOID lpParam);

DWORD WINAPI PM_CreateWindowEx_setup(HMServiceStruct* pData);

// Hook per la notifica di creazione di nuove finestre
typedef struct {
	COMMONDATA;
} CreateWindowExStruct;

extern CreateWindowExStruct CreateWindowExData;
