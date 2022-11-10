extern void SocialWinHttpSetup(const WCHAR *DestURL);
DWORD HttpSocialRequest(const WCHAR* Host, const WCHAR* verb, const WCHAR* resource, DWORD port, BYTE* s_buffer, DWORD sbuf_len, BYTE** r_buffer, DWORD* response_len, char* cookies);

