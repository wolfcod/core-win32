#pragma once

#ifndef __PROCESS_H
#define __PROCESS_H

DWORD HM_FindPid(LPCSTR lpProcessName, BOOL my_flag);

BOOL IsMyProcess(DWORD pid);
char* HM_FindProc(DWORD);
WCHAR* HM_FindProcW(DWORD);
HWND HM_GetProcessWindow(char* procname);

#endif

