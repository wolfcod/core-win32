#pragma once

#ifndef _STRINGS_H
#define _STRINGS_H

WCHAR* UTF8_2_UTF16(char* str);

int CmpWildW(WCHAR* wild, WCHAR* string);
int CmpWild(const unsigned char* wild, const unsigned char* string);
#endif

