#include <Windows.h>
#include <strsafe.h>
#include "common.h"
#include "process.h"

struct EnumerateProcess
{
	HANDLE hHandle;
	PROCESSENTRY32 pe32;

	EnumerateProcess()
		: hHandle(NULL)
	{
	}

	~EnumerateProcess()
	{
		if (hHandle != INVALID_HANDLE_VALUE && hHandle != NULL) {
			CloseHandle(hHandle);
			hHandle = NULL;
		}
	}

	BOOL fetch() {
		if (hHandle == NULL) {
			memset(&pe32, 0, sizeof(PROCESSENTRY32));
			pe32.dwSize = sizeof(PROCESSENTRY32);
			hHandle = FNC(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);

			if (!FNC(Process32First)(hHandle, &pe32)) {
				CloseHandle(hHandle);
				hHandle = INVALID_HANDLE_VALUE;
				return FALSE;
			}
			return TRUE;
		}
		else if (hHandle == INVALID_HANDLE_VALUE) {
		}
		else {
			if (FNC(Process32Next)(hHandle, &pe32) == FALSE) {
				CloseHandle(hHandle);
			}
		}

		if (hHandle == INVALID_HANDLE_VALUE || hHandle == NULL)
			return FALSE;

		return TRUE;
	}

	bool operator() () {
		if (fetch() == FALSE)
			return false;

		return true;
	}

};

struct EnumerateProcessW
{
	HANDLE hHandle;
	PROCESSENTRY32W pe32;

	EnumerateProcessW()
		: hHandle(NULL)
	{
	}

	~EnumerateProcessW()
	{
		if (hHandle != INVALID_HANDLE_VALUE && hHandle != NULL) {
			CloseHandle(hHandle);
			hHandle = NULL;
		}
	}

	BOOL fetch() {
		if (hHandle == NULL) {
			memset(&pe32, 0, sizeof(PROCESSENTRY32W));
			pe32.dwSize = sizeof(PROCESSENTRY32W);
			hHandle = FNC(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);

			if (!FNC(Process32FirstW)(hHandle, &pe32)) {
				CloseHandle(hHandle);
				hHandle = INVALID_HANDLE_VALUE;
				return FALSE;
			}
			return TRUE;
		}
		else if (hHandle == INVALID_HANDLE_VALUE) {
		}
		else {
			if (FNC(Process32NextW)(hHandle, &pe32) == FALSE) {
				CloseHandle(hHandle);
			}
		}

		if (hHandle == INVALID_HANDLE_VALUE || hHandle == NULL)
			return FALSE;

		return TRUE;
	}

	bool find(DWORD dwPid) {
		while (fetch()) {
			if (pe32.th32ProcessID == dwPid)
				return true;
		}

		return false;
	}

	bool operator() () {
		if (fetch() == FALSE)
			return false;

		return true;
	}


};

typedef struct {
	HWND proc_window;
	DWORD pid;
} PROC_WINDOW;

BOOL CALLBACK IsProcWindow(HWND hwnd, LPARAM param)
{
	PROC_WINDOW* pstr = (PROC_WINDOW*)param;
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
	PROC_WINDOW proc_window;
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
	DWORD dwPID = 0;
	char* name_offs;
	char* ret_name = NULL;

	EnumerateProcess processes;

	// Cicla la lista dei processi attivi
	while (processes()) {
		if (processes.pe32.th32ProcessID == pid) {
			// Elimina il path
			name_offs = strrchr(processes.pe32.szExeFile, '\\');
			if (!name_offs)
				name_offs = processes.pe32.szExeFile;
			else
				name_offs++;
			ret_name = _strdup(name_offs);
			break;
		}

	}

	return ret_name;
}

// Ritorna il nome del processo "pid"
// Torna NULL se non ha trovato niente 
// N.B. Se torna una stringa, va liberata
WCHAR* HM_FindProcW(DWORD pid)
{
	DWORD dwPID = 0;
	WCHAR* name_offs;
	WCHAR* ret_name = NULL;

	EnumerateProcessW proc;

	while (proc.find(pid)) {
		// Elimina il path
		name_offs = wcsrchr(proc.pe32.szExeFile, L'\\');
		if (!name_offs)
			name_offs = proc.pe32.szExeFile;
		else
			name_offs++;
		ret_name = _wcsdup(name_offs);
		break;
	}

	return ret_name;
}

static BOOL HM_FindProcPath(DWORD pid, LPWSTR lpFilename, DWORD len)
{
	HANDLE hProc = OpenProcess(0x410, FALSE, pid);
	DWORD n = 0;

	if (hProc != NULL) {
		n = GetModuleFileNameExW(hProc, NULL, lpFilename, len);
		CloseHandle(hProc);
	}
	
	return (n != 0) ? TRUE : FALSE;
}

typedef struct {
	WORD wLanguage;
	WORD wCodePage;
} LANGANDCODEPAGE;

// Ritorna la descrizione di un processo dato il PID
BOOL ReadDesc(DWORD pid, WCHAR* file_desc, DWORD len)
{
	UINT cbTranslate = 0, desc_size = 0;
	WCHAR* description;
	WCHAR file_path[MAX_PATH];
	BYTE SubBlock[100];
	
	LANGANDCODEPAGE *lpTranslate;

	if (!HM_FindProcPath(pid, file_path, sizeof(file_path)))
		return FALSE;

	DWORD dummy = 0;
	DWORD size = GetFileVersionInfoSizeW(file_path, &dummy);
	if (size == 0)
		return FALSE;

	BYTE* pBlock = (BYTE*)malloc(size);
	
	if (!pBlock)
		return FALSE;

	if (!GetFileVersionInfoW(file_path, 0, size, pBlock)) {
		free(pBlock);
		return FALSE;
	}

	BOOL r = VerQueryValueW(pBlock, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate);
	if (!r|| cbTranslate < sizeof(LANGANDCODEPAGE)) {
		free(pBlock);
		return FALSE;
	}

	ZeroMemory(SubBlock, sizeof(SubBlock));
	HRESULT hr = StringCchPrintfW((STRSAFE_LPWSTR)SubBlock, sizeof(SubBlock) - 1, L"\\StringFileInfo\\%04x%04x\\FileDescription", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
	r = FALSE;
	if (SUCCEEDED(hr)) {
		if (VerQueryValueW(pBlock, (LPCWSTR)SubBlock, (LPVOID*)&description, &desc_size)) {
			_snwprintf_s(file_desc, len / sizeof(WCHAR), _TRUNCATE, L"%s", description);
			r = TRUE;
		}
	}

	free(pBlock);
	return r;
}

// Torna TRUE se il processo e' dell'utente
// chiamante
BOOL IsMyProcess(DWORD pid)
{
	char wsRefDomain[512], wsUserName[512], wsEffectiveName[512];
	SID_NAME_USE peUse;
	BOOL ret_val = FALSE;
	DWORD dwLen = 0, cbUserName = sizeof(wsUserName), cbRefDomain = sizeof(wsRefDomain), cbEffectiveName = sizeof(wsEffectiveName);

	HANDLE hProc = FNC(OpenProcess)(PROCESS_QUERY_INFORMATION, FALSE, pid);

	if (hProc != NULL) {
		HANDLE hToken = NULL;
		TOKEN_USER* token_owner = NULL;

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
DWORD HM_FindPid(LPCSTR lpProcessName, BOOL my_flag)
{
	DWORD dwPID = 0;
	char* name_offs;

	EnumerateProcess processes;

	// Cicla la lista dei processi attivi
	while (processes()) {
		name_offs = strrchr(processes.pe32.szExeFile, '\\');
		if (!name_offs)
			name_offs = processes.pe32.szExeFile;
		else
			name_offs++;

		// Cerca il processo confrontando il nome
		if (!_stricmp(name_offs, lpProcessName)) {
			if (!my_flag || IsMyProcess(processes.pe32.th32ProcessID)) {
				dwPID = processes.pe32.th32ProcessID;
				break;
			}
		}
	}

	return dwPID;
}
