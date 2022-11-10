#pragma once
#ifndef __SCRAMBLE_STRING_H
#define __SCRAMBLE_STRING_H

struct ScrambleString
{
	operator const char* ()
	{
		return (string != NULL) ? string : (char*)"NIL";
	}

	operator const wchar_t* ()
	{
		return string_w;
	}

	char* get_str()
	{
		return (string != NULL) ? string : (char *) "NIL";
	}

	wchar_t* get_wstr()
	{
		return string_w;
	}

	ScrambleString(const char* ob_str)
	{
		string = LOG_ScrambleName((char*)ob_str, 2, FALSE);
		if (string)
			_snwprintf_s(string_w, 64, _TRUNCATE, L"%S", string);
		else
			_snwprintf_s(string_w, 64, _TRUNCATE, L"NIL");
	}

	ScrambleString(char* ob_str, BOOL is_demo)
	{
		string = NULL;
		if (is_demo) {
			string = LOG_ScrambleName(ob_str, 2, FALSE);
			if (string)
				_snwprintf_s(string_w, 64, _TRUNCATE, L"%S", string);
			else
				_snwprintf_s(string_w, 64, _TRUNCATE, L"NIL");
		}
		else
			_snwprintf_s(string_w, 64, _TRUNCATE, L"");
	}

	~ScrambleString(void)
	{
		SAFE_FREE(string);
	}


	char* string;
	WCHAR string_w[64];
};

#endif
