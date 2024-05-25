
typedef DWORD(__stdcall* GetCurrentProcessId_t)(void);
typedef struct {
	COMMONDATA;
	GetCurrentProcessId_t pGetCurrentProcessId;
} CreateFileStruct;
extern CreateFileStruct CreateFileData;

typedef struct {
	char szFileName[MAXFILELEN];
	DWORD dwOperation;
	DWORD dwPid;
} IPCCreateFileStruct;

// -- Wrapper CreateFileA e CreateFileW
HANDLE _stdcall PM_CreateFile(DWORD ARG1,
	DWORD ARG2,
	DWORD ARG3,
	DWORD ARG4,
	DWORD ARG5,
	DWORD ARG6,
	DWORD ARG7);
DWORD PM_CreateFile_setup(HMServiceStruct* pData);
// -- Wrapper DeleteFileA e DeleteFileW
BOOL _stdcall PM_DeleteFile(DWORD ARG1);

// -- Wrapper MoveFileA e MoveFileW
BOOL _stdcall PM_MoveFile(DWORD ARG1, DWORD ARG2);

