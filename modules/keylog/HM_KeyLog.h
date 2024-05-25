#pragma once

typedef struct {
	DWORD msg;
	DWORD lprm;
	DWORD wprm;
} KEY_PARAMS;

BOOL _stdcall PM_GetMessage(DWORD ARG1,
	DWORD ARG2,
	DWORD ARG3,
	DWORD ARG4);

