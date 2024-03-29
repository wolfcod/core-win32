#define ELEM_DELIMITER 0xABADC0DE

class bin_buf
{
public :
	bin_buf(void) { buf_ptr = NULL; buf_len = 0; }
	~bin_buf(void) { if (buf_ptr) free(buf_ptr); }

	BOOL add(void *abuf, size_t alen) {
		BYTE *tmp_buf;
		if (alen<=0 || abuf == NULL)
			return FALSE;
		tmp_buf = (BYTE *)realloc(buf_ptr, buf_len + alen);
		if (!tmp_buf)
			return FALSE;
		buf_ptr = tmp_buf;
		memcpy(buf_ptr+buf_len, abuf, alen);
		buf_len += alen;
		return TRUE;
	}

	BOOL add(const wchar_t* str) {
		return add((void*)str, (wcslen(str) + 1) * 2);
	}

	BOOL add(const char* str) {
		return add((void*)str, strlen(str) + 1);
	}

	BYTE *get_buf(void) { return buf_ptr; }
	DWORD get_len(void) { return (DWORD)buf_len; }
private:
	BYTE *buf_ptr;
	size_t buf_len;
};


#define GET_TIME(x)	{__int64 aclock;\
	                 _time64( &aclock );\
					 _gmtime64_s(&x, &aclock);\
					 x.tm_year += 1900;\
					 x.tm_mon ++;}

template<typename T>
__forceinline void write_buff(bin_buf& dst, const T *value)
{
	dst.add((void *)value, sizeof(T));
}

template<>
__forceinline void write_buff(bin_buf& dst, const char *str)
{
	dst.add(str);
}

template<>
__forceinline void write_buff(bin_buf& dst, const wchar_t* str)
{
	dst.add(str);
}
