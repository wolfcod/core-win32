#include <Windows.h>
#include <string>
#include "../HM_PWDAgent/base64.h"

char *base64_encodeY(const unsigned char* input, int length)
{
    if (input == NULL)
        return NULL;

    std::string str = base64_encode(input, length);

    char* dst = (char*)malloc(str.size() + 1);
    if (dst != NULL) {
        memset(dst, 0, str.size() + 1);
        memcpy(dst, str.c_str(), str.size());
    }
    return dst;
}

inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

unsigned char *base64_decodeY(const char *input, int length, int *outlen)
{
    std::string str = base64_decode(input);

    int i = 0;
    int j = 0;
    int r = 0;
    int idx = 0;
    unsigned char char_array_4[4], char_array_3[3];
    unsigned char *output = (unsigned char *)malloc(length*3/4);

    while (length-- && input[idx] != '=') {
	//skip invalid or padding based chars
	if (!is_base64(input[idx])) {
	    idx++;
	    continue;
	}
        char_array_4[i++] = input[idx++];
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = strchr(base64_chars, char_array_4[i]) - base64_chars;

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                output[r++] = char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++)
            char_array_4[j] = 0;

        for (j = 0; j <4; j++)
            char_array_4[j] = strchr(base64_chars, char_array_4[j]) - base64_chars;

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++)
            output[r++] = char_array_3[j];
    }

    *outlen = r;

    return output;
}