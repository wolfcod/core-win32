#pragma once

#ifndef __H4DLL_CONFIG_H
#define __H4DLL_CONFIG_H

struct cJSON;

typedef void (WINAPI* conf_callback_t)(cJSON*, DWORD counter);

BOOL HM_ParseConfGlobals(char* conf, conf_callback_t call_back);
void HM_UpdateGlobalConf();
void UnlockConfFile();

#define IMAGE_QUALITY_LOW		10
#define IMAGE_QUALITY_MEDIUM	50
#define IMAGE_QUALITY_HIGH		100

DWORD config_get_quality(cJSON*);

#endif
