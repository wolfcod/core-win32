#include <Windows.h>
#include <strsafe.h>
#include "common.h"
#include "process.h"

typedef struct {
	HWND proc_window;
	DWORD pid;
} proc_window_struct;

BOOL CALLBACK IsProcWindow(HWND hwnd, LPARAM param)
{
	proc_window_struct* pstr = (proc_window_struct*)param;
	DWORD pid;
	if (GetWindowLong(hwnd, GWL_HWNDPARENT) != NULL)
		return TRUE;
	if (!IsWindowVisible(hwnd))
		return TRUE;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid == pstr->pid) {
		pstr->proc_window = hwnd;
		return FALSE;
	}
	return TRUE;
}
// Torna la finestra del processo "procname"
HWND HM_GetProcessWindow(char* procname)
{
	proc_window_struct proc_window;
	proc_window.proc_window = NULL;
	proc_window.pid = HM_FindPid(procname, TRUE);
	if (proc_window.pid == 0)
		return NULL;

	EnumWindows(IsProcWindow, (LPARAM)(&proc_window));
	return proc_window.proc_window;
}

// Ritorna il nome del processo "pid"
// Torna NULL se non ha trovato niente 
// N.B. Se torna una stringa, va liberata
char* HM_FindProc(DWORD pid)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD dwPID = 0;
	char* name_offs;
	char* ret_name = NULL;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if ((hProcessSnap = FNC(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
		return NULL;

	if (!FNC(Process32First)(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return NULL;
	}

	// Cicla la lista dei processi attivi
	do {
		// Cerca il processo "pid"
		if (pe32.th32ProcessID == pid) {
			// Elimina il path
			name_offs = strrchr(pe32.szExeFile, '\\');
			if (!name_offs)
				name_offs = pe32.szExeFile;
			else
				name_offs++;
			ret_name = _strdup(name_offs);
			break;
		}
	} while (FNC(Process32Next)(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return ret_name;
}

// Ritorna il nome del processo "pid"
// Torna NULL se non ha trovato niente 
// N.B. Se torna una stringa, va liberata
WCHAR* HM_FindProcW(DWORD pid)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32W pe32;
	DWORD dwPID = 0;
	WCHAR* name_offs;
	WCHAR* ret_name = NULL;

	pe32.dwSize = sizeof(pe32);
	if ((hProcessSnap = FNC(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
		return NULL;

	if (!FNC(Process32FirstW)(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return NULL;
	}

	// Cicla la lista dei processi attivi
	do {
		// Cerca il processo "pid"
		if (pe32.th32ProcessID == pid) {
			// Elimina il path
			name_offs = wcsrchr(pe32.szExeFile, L'\\');
			if (!name_offs)
				name_offs = pe32.szExeFile;
			else
				name_offs++;
			ret_name = _wcsdup(name_offs);
			break;
		}
	} while (FNC(Process32NextW)(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return ret_name;
}

BOOL HM_FindProcPath(DWORD pid, WCHAR* file_path, DWORD len)
{
	HANDLE hProc;

	hProc = OpenProcess(0x410, FALSE, pid);
	if (hProc == NULL)
		return FALSE;

	if (GetModuleFileNameExW(hProc, NULL, file_path, len) > 0) {
		CloseHandle(hProc);
		return TRUE;
	}

	CloseHandle(hProc);
	return FALSE;
}

// Ritorna la descrizione di un processo dato il PID
BOOL ReadDesc(DWORD pid, WCHAR* file_desc, DWORD len)
{
	HRESULT hr;
	DWORD size, dummy;
	BYTE* pBlock;
	UINT cbTranslate = 0, desc_size = 0;
	WCHAR* description;
	WCHAR file_path[MAX_PATH];
	BOOL ret_val;
	BYTE SubBlock[100];
	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	if (!HM_FindProcPath(pid, file_path, sizeof(file_path)))
		return FALSE;

	size = GetFileVersionInfoSizeW(file_path, &dummy);
	if (size == 0)
		return FALSE;

	pBlock = (BYTE*)malloc(size);
	if (!pBlock)
		return FALSE;

	if (!GetFileVersionInfoW(file_path, 0, size, pBlock)) {
		free(pBlock);
		return FALSE;
	}

	ret_val = VerQueryValueW(pBlock, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate);
	if (!ret_val || cbTranslate < sizeof(struct LANGANDCODEPAGE)) {
		free(pBlock);
		return FALSE;
	}

	ZeroMemory(SubBlock, sizeof(SubBlock));
	hr = StringCchPrintfW((STRSAFE_LPWSTR)SubBlock, sizeof(SubBlock) - 1, L"\\StringFileInfo\\%04x%04x\\FileDescription", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
	if (FAILED(hr)) {
		free(pBlock);
		return FALSE;
	}

	if (VerQueryValueW(pBlock, (LPCWSTR)SubBlock, (LPVOID*)&description, &desc_size)) {
		_snwprintf_s(file_desc, len / sizeof(WCHAR), _TRUNCATE, L"%s", description);
		free(pBlock);
		return TRUE;
	}

	free(pBlock);
	return FALSE;
}

// Torna TRUE se il processo e' dell'utente
// chiamante
BOOL IsMyProcess(DWORD pid)
{
	HANDLE hProc = 0;
	HANDLE hToken = 0;
	TOKEN_USER* token_owner = NULL;
	char wsRefDomain[512], wsUserName[512], wsEffectiveName[512];
	SID_NAME_USE peUse;
	BOOL ret_val = FALSE;
	DWORD dwLen = 0, cbUserName = sizeof(wsUserName), cbRefDomain = sizeof(wsRefDomain), cbEffectiveName = sizeof(wsEffectiveName);

	hProc = FNC(OpenProcess)(PROCESS_QUERY_INFORMATION, FALSE, pid);

	if (hProc) {
		if (FNC(OpenProcessToken)(hProc, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken)) {
			FNC(GetTokenInformation)(hToken, TokenUser, token_owner, 0, &dwLen);
			if (dwLen)
				token_owner = (TOKEN_USER*)malloc(dwLen);
			if (token_owner) {
				memset(token_owner, 0, dwLen);
				if (FNC(GetTokenInformation)(hToken, TokenUser, token_owner, dwLen, &dwLen))
					if (FNC(LookupAccountSidA)(NULL, token_owner->User.Sid, wsUserName, &cbUserName, wsRefDomain, &cbRefDomain, &peUse))
						if (FNC(GetUserNameA)(wsEffectiveName, &cbEffectiveName))
							if (!_stricmp(wsEffectiveName, wsUserName))
								ret_val = TRUE;
				free(token_owner);
			}
			CloseHandle(hToken);
		}
		CloseHandle(hProc);
	}

	return ret_val;
}

// Ritorna il PID del processo "proc_name"
// Torna 0 se non lo trova
// Se my_flag e' settato, torna solo i processi
// dell'utente chiamante
DWORD HM_FindPid(char* proc_name, BOOL my_flag)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD dwPID = 0;
	char* name_offs;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if ((hProcessSnap = FNC(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
		return 0;

	if (!FNC(Process32First)(hProcessSnap, &pe32)) {
		CloseHandle(hProcessSnap);
		return 0;
	}

	// Cicla la lista dei processi attivi
	do {
		// Elimina il path
		name_offs = strrchr(pe32.szExeFile, '\\');
		if (!name_offs)
			name_offs = pe32.szExeFile;
		else
			name_offs++;

		// Cerca il processo confrontando il nome
		if (!_stricmp(name_offs, proc_name)) {
			if (!my_flag || IsMyProcess(pe32.th32ProcessID)) {
				dwPID = pe32.th32ProcessID;
				break;
			}
		}
	} while (FNC(Process32Next)(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return dwPID;
}

