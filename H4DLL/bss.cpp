#include <Windows.h>
#include "common.h"

#include "bss.h"

#pragma bss_seg("shared")
BSS_SEG shared;
#pragma bss_seg()
#pragma comment(linker, "/section:shared,RWS")
