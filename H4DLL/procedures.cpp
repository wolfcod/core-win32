#include <Windows.h>
#include <winternl.h>
extern "C" void WINAPI HIDING(void)
{
	return;
}

extern "C" BOOL WINAPI InternalIsDebuggerPresent()
{
#ifdef _WIN64
#else
	__readfsdword(0x18);
#endif
}