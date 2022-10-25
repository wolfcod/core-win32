#pragma once

#ifndef __PROCESS_H
#define __PROCESS_H

DWORD HM_FindPid(char* proc_name, BOOL my_flag);
DWORD HM_FindPid(char*, BOOL);
BOOL IsMyProcess(DWORD pid);
char* HM_FindProc(DWORD);
WCHAR* HM_FindProcW(DWORD);
DWORD HM_FindPid(char* proc_name, BOOL my_flag);
HWND HM_GetProcessWindow(char* procname);

#endif

