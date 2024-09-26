#ifndef __PEB_H
#define __PEB_H

typedef struct _peb_list_entry PEB_LIST_ENTRY, * PPEB_LIST_ENTRY;

PEB_LIST_ENTRY* GetPEBAdd();

// Elimina il modulo hMod
void HidePEB(HMODULE hMod);

#endif
