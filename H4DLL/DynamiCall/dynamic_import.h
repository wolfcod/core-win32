#ifndef dynamic_import_h__
#define dynamic_import_h__

#include <Windows.h>
#include "obfuscated_calls.h"

template<typename T, int size>
struct ShiftBy1
{
    T value[size];
    bool b;
    const T* get()
    {
        if (b == false) {
            for (int i = 0; i < size; i++) {
                value[i] -= 1;
            }
            b = true;
        }
        return value;
    }


    template<int index>
    constexpr inline void assign(const T* ptr)
    {
        value[index] = ptr[index] + 1;
        assign<index - 1>(ptr);
    }

    template<>
    constexpr inline void assign<0>(const T* ptr)
    {
        value[0] = *ptr + 1;
    }

    inline ShiftBy1(const T* ptr)
        : b(false)
    {
        value[size] = 0;
        assign<size - 1>(ptr);
    }
};

struct hash_dj2b
{
    unsigned long hash;

    constexpr inline unsigned long next(unsigned long h, const char* str)
    {
        if (*str == 0)
            return h;

        h = ((h << 5) + h) + *str;

        return next(h, str + 1);
    }


    inline hash_dj2b(const char* str)
    {
        hash = next(5381, str);
    }
};

typedef struct _XREF_CALLS
{
    unsigned long hash;
	ULONG_PTR ptr;
} XREFCALL;

typedef struct _XREF_DLL
{
	char *name;
	XREFCALL calls[256];
} XREFDLL;

#define STRINGIFY(x) #x
#define OBFUSCATED(x) #x

#define IMPORT_DLL(n) { OBFUSCATED(n), {
#define IMPORT_CALL(n) { hash_dj2b(#n).hash, NULL },
#define NULL_IMPORT_CALL { NULL, NULL },
#define END_DLL NULL_IMPORT_CALL } },

#define END_IMPORTING { NULL, { NULL } }

ULONG_PTR dynamic_call(const TCHAR* name);

// #define FNC(x) ((PROTO_##x) dynamic_call( STRINGIFY(x) ))
#define FNC(x) ((PROTO_##x) dynamic_call( ShiftBy1<char, sizeof(#x)>(#x).get() ))


extern void shiftBy1(char *str);

#endif // dynamic_import_h__