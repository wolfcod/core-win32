#include <windows.h>

#define ibaseDD *(PDWORD)&ibase
#define RVATOVA(base,offset) ((PVOID)((DWORD)(base)+(DWORD)(offset)))

typedef struct {
    WORD    offset:12;
    WORD    type:4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;

struct FixupBlock
{
	unsigned long pageRVA;
	unsigned long blockSize;
};

extern DWORD GetHeaders(PCHAR ibase,
                 PIMAGE_FILE_HEADER *pFH,
                 PIMAGE_OPTIONAL_HEADER *pOH,
                 PIMAGE_SECTION_HEADER *pSH);
extern DWORD FindKiServiceTable(HMODULE hModule,DWORD dwKSDT);
extern BOOL RelocImage(PVOID exeAddr, PVOID newAddr);
LPVOID loadDLL(char *dllName);

