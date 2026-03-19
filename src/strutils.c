#include "strutils.h"

char str_toLower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + 32;
    return c;
}

int str_cmp(const char* a, const char* b)
{
    while (*a && *b)
    {
        if (str_toLower(*a) != str_toLower(*b))
            break;

        a++;
        b++;
    }

    return str_toLower(*a) - str_toLower(*b);
}

//--------------------------------------------------
// Managing ANSI strings - case insensitive
//--------------------------------------------------
DWORD str_hash_ROR13(const char *str)
{
    DWORD hash = 0;

    while (*str)
    {
        hash = (hash >> 13) | (hash << (32 - 13));
        hash += str_toLower(*str);
        str++;
    }

    return hash;
}

//--------------------------------------------------
// Managing UFT-16 strings - case insensitive
//--------------------------------------------------
DWORD str_hash_ROR13_w(const wchar_t* str)
{
    DWORD hash = 0;

    while (*str)
    {
        wchar_t c = *str++;
        if (c >= L'A' && c <= L'Z')
            c += 32;

        hash = (hash >> 13) | (hash << (32 - 13));
        hash += (BYTE)c;
    }

    return hash;
}

wchar_t* str_wcsrchr(const wchar_t* str, wchar_t ch)
{
    const wchar_t* last = NULL;

    while (*str)
    {
        if (*str == ch)
            last = str;
        str++;
    }

    return (wchar_t*)last;
}
