#include <Windows.h>
#include <TlHelp32.h>
#include "enumprocess.h"

#define FNC(x) x

EnumerateProcess::EnumerateProcess()
	: hHandle(NULL)
{
	memset(&pe32, 0, sizeof(PROCESSENTRY32));
}

EnumerateProcess::~EnumerateProcess()
{
	if (hHandle != NULL) {
		CloseHandle(hHandle);
		hHandle = NULL;
	}
}

PROCESSENTRY32* EnumerateProcess::operator*() {
	return &pe32;
}

BOOL EnumerateProcess::fetch() {
	if (hHandle == NULL) {
		memset(&pe32, 0, sizeof(PROCESSENTRY32));
		pe32.dwSize = sizeof(PROCESSENTRY32);
		hHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (!Process32First(hHandle, &pe32)) {
			CloseHandle(hHandle);
			hHandle = NULL;
			return FALSE;
		}
		return TRUE;
	}
	else {
		if (Process32Next(hHandle, &pe32) == FALSE) {
			CloseHandle(hHandle);
			hHandle = NULL;
		}
	}

	return (hHandle != NULL);
}

bool EnumerateProcess::operator() () {
	if (fetch() == FALSE)
		return false;

	return true;
}

EnumerateProcessW::EnumerateProcessW()
	: hHandle(NULL)
{
	memset(&pe32, 0, sizeof(PROCESSENTRY32W));
}

EnumerateProcessW::~EnumerateProcessW()
{
	if (hHandle != INVALID_HANDLE_VALUE && hHandle != NULL) {
		CloseHandle(hHandle);
		hHandle = NULL;
	}
}

BOOL EnumerateProcessW::fetch() {
	if (hHandle == NULL) {
		memset(&pe32, 0, sizeof(PROCESSENTRY32W));
		pe32.dwSize = sizeof(PROCESSENTRY32W);
		hHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (!Process32FirstW(hHandle, &pe32)) {
			CloseHandle(hHandle);
			hHandle = INVALID_HANDLE_VALUE;
			return FALSE;
		}
		return TRUE;
	}
	else if (hHandle == INVALID_HANDLE_VALUE) {
	}
	else {
		if (Process32NextW(hHandle, &pe32) == FALSE) {
			CloseHandle(hHandle);
		}
	}

	if (hHandle == INVALID_HANDLE_VALUE || hHandle == NULL)
		return FALSE;

	return TRUE;
}

bool EnumerateProcessW::find(DWORD dwPid) {
	while (fetch()) {
		if (pe32.th32ProcessID == dwPid)
			return true;
	}

	return false;
}

bool EnumerateProcessW::operator() () {
	if (fetch() == FALSE)
		return false;

	return true;
}

PROCESSENTRY32W* EnumerateProcessW::operator*() {
	return &pe32;
}

EnumerateModule::EnumerateModule()
	: hHandle(NULL), dwPid(NULL)
{
	memset(&me32, 0, sizeof(MODULEENTRY32));
}

EnumerateModule::EnumerateModule(DWORD dwPid)
	: hHandle(NULL)
{
	memset(&me32, 0, sizeof(MODULEENTRY32));
	this->dwPid = dwPid;
}

EnumerateModule::~EnumerateModule()
{
	if (hHandle != NULL) {
		CloseHandle(hHandle);
		hHandle = NULL;
	}
}

MODULEENTRY32* EnumerateModule::operator*() {
	return &me32;
}

BOOL EnumerateModule::fetch() {
	if (hHandle == NULL) {
		memset(&me32, 0, sizeof(MODULEENTRY32));
		me32.dwSize = sizeof(MODULEENTRY32);
		hHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);

		if (!Module32First(hHandle, &me32)) {
			CloseHandle(hHandle);
			hHandle = NULL;
			return FALSE;
		}
		return TRUE;
	}
	else {
		if (Module32Next(hHandle, &me32) == FALSE) {
			CloseHandle(hHandle);
			hHandle = NULL;
		}
	}

	return (hHandle != NULL);
}

bool EnumerateModule::operator() () {
	if (fetch() == FALSE)
		return false;

	return true;
}
