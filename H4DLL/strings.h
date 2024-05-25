#pragma once

#ifndef _STRINGS_H
#define _STRINGS_H

WCHAR* UTF8_2_UTF16(char* str);
void HM_A2U(char* src, char* dst);
void HM_U2A(char* buffer);
char* HM_memstr(char*, char*);

int CmpWildW(LPWSTR  wild, LPWSTR string);
int CmpWild(LPSTR wild, LPSTR string);
#endif

