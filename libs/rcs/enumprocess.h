#pragma once

struct EnumerateProcess
{
	HANDLE hHandle;
	PROCESSENTRY32 pe32;

	EnumerateProcess();

	~EnumerateProcess();
	PROCESSENTRY32* operator*();
	BOOL fetch();

	bool operator() ();
};

struct EnumerateModule
{
	HANDLE hHandle;
	MODULEENTRY32 me32;
	DWORD dwPid;

	EnumerateModule();
	EnumerateModule(DWORD dwPid);
	~EnumerateModule();

	MODULEENTRY32* operator*();
	BOOL fetch();

	bool operator() ();
};
struct EnumerateProcessW
{
	HANDLE hHandle;
	PROCESSENTRY32W pe32;

	PROCESSENTRY32W* operator*();

	EnumerateProcessW();

	~EnumerateProcessW();

	BOOL fetch();
	bool find(DWORD dwPid);
	bool operator() ();
};