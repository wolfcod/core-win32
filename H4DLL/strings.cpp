#include <Windows.h>

/// <summary>
/// 
/// </summary>
/// <param name="str"></param>
/// <returns></returns>
WCHAR* UTF8_2_UTF16(char* str)
{
	DWORD wclen;
	WCHAR* wcstr;

	if ((wclen = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0)) == 0)
		return NULL;

	if (!(wcstr = (WCHAR*)malloc(wclen * sizeof(WCHAR))))
		return NULL;

	if (MultiByteToWideChar(CP_UTF8, 0, str, -1, wcstr, wclen) == 0) {
		free(wcstr);
		return NULL;
	}

	return wcstr;
}
