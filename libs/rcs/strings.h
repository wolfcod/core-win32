#pragma once

#ifndef _STRINGS_H
#define _STRINGS_H

WCHAR* UTF8_2_UTF16(char* str);

void HM_A2U(char* src, wchar_t* dst);

int CmpWildW(LPWSTR  wild, LPWSTR string);

int CmpWild(LPSTR wild, LPSTR string);

#endif

