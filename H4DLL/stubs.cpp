#include <Windows.h>
#include "common.h"

BOOL WINAPI virtualFreeEx(_In_ HANDLE hProcess, LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD dwFreeType)
{
	return FNC(VirtualFreeEx)(hProcess, lpAddress, dwSize, dwFreeType);
}

HANDLE WINAPI openProcess(_In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ DWORD dwProcessId)
{
	return FNC(OpenProcess)(dwDesiredAccess, bInheritHandle, dwProcessId);
}

