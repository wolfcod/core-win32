#include <Windows.h>

/// <summary>
/// 
/// </summary>
/// <param name="str"></param>
/// <returns></returns>
WCHAR* UTF8_2_UTF16(char* str)
{
	DWORD wclen;
	WCHAR* wcstr;

	if ((wclen = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0)) == 0)
		return NULL;

	if (!(wcstr = (WCHAR*)malloc(wclen * sizeof(WCHAR))))
		return NULL;

	if (MultiByteToWideChar(CP_UTF8, 0, str, -1, wcstr, wclen) == 0) {
		free(wcstr);
		return NULL;
	}

	return wcstr;
}


// Converte Unicode in ascii
void HM_U2A(char* buffer)
{
	DWORD i = 0, j = 0;
	if (!buffer || buffer[1] != 0)
		return;

	do {
		i++;
		j += 2;
		buffer[i] = buffer[j];
	} while (buffer[i] != 0);
}

void HM_A2U(char* src, char* dst)
{
	DWORD i = 0;
	do {
		dst[i * 2] = src[i];
		dst[i * 2 + 1] = 0;
	} while (src[i++]);
}

// Ritorna il puntatore a dopo una stringa trovata in memoria
char* HM_memstr(char* memory, char* string)
{
	char* ptr;
	ptr = memory;

	for (;;) {
		if (!strcmp(ptr, string))
			return (ptr + strlen(string) + 1);
		ptr++;
	}
}

/* Return the first occurrence of NEEDLE in HAYSTACK. */
#define __builtin_expect(expr, val)   (expr)
void* memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len)
{
	/* not really Rabin-Karp, just using additive hashing */
	char* haystack_ = (char*)haystack;
	char* needle_ = (char*)needle;
	int hash = 0;		/* this is the static hash value of the needle */
	int hay_hash = 0;	/* rolling hash over the haystack */
	char* last;
	size_t i;

	if (haystack_len < needle_len)
		return NULL;

	if (!needle_len)
		return haystack_;

	/* initialize hashes */
	for (i = needle_len; i; --i)
	{
		hash += *needle_++;
		hay_hash += *haystack_++;
	}

	/* iterate over the haystack */
	haystack_ = (char*)haystack;
	needle_ = (char*)needle;
	last = haystack_ + (haystack_len - needle_len + 1);
	for (; haystack_ < last; ++haystack_)
	{
		if (__builtin_expect(hash == hay_hash, 0) &&
			*haystack_ == *needle_ &&	/* prevent calling memcmp, was a optimization from existing glibc */
			!memcmp(haystack_, needle_, needle_len))
			return haystack_;

		/* roll the hash */
		hay_hash -= *haystack_;
		hay_hash += *(haystack_ + needle_len);
	}

	return NULL;
}

// Compara due stringhe con wildcard
// torna 0 se le stringhe sono diverse
int CmpWildW(WCHAR* wild, WCHAR* string)
{
	WCHAR* cp = NULL, * mp = NULL;

	while ((*string) && (*wild != '*')) {
		if ((towupper((WCHAR)*wild) != towupper((WCHAR)*string)) && (*wild != '?')) {
			return 0;
		}
		wild++;
		string++;
	}

	while (*string) {
		if (*wild == '*') {
			if (!*++wild) {
				return 1;
			}

			mp = wild;
			cp = string + 1;
		}
		else if ((towupper((WCHAR)*wild) == towupper((WCHAR)*string)) || (*wild == '?')) {
			wild++;
			string++;
		}
		else {
			wild = mp;
			string = cp++;
		}
	}

	while (*wild == '*') {
		wild++;
	}

	return !*wild;
}

// Compara due stringhe con wildcard
// torna 0 se le stringhe sono diverse
int CmpWild(const unsigned char* wild, const unsigned char* string) {
	const unsigned char* cp = NULL, * mp = NULL;

	while ((*string) && (*wild != '*')) {
		if ((toupper((unsigned int)*wild) != toupper((unsigned int)*string)) && (*wild != '?')) {
			return 0;
		}
		wild++;
		string++;
	}

	while (*string) {
		if (*wild == '*') {
			if (!*++wild) {
				return 1;
			}
			mp = wild;
			cp = string + 1;
		}
		else if ((toupper((unsigned int)*wild) == toupper((unsigned int)*string)) || (*wild == '?')) {
			wild++;
			string++;
		}
		else {
			wild = mp;
			string = cp++;
		}
	}

	while (*wild == '*') {
		wild++;
	}
	return !*wild;
}
