#ifndef STRUTILS_H
#define STRUTILS_H

#include <minwindef.h>

char str_toLower(char c);
int str_cmp(const char* a, const char* b);
DWORD str_hash_ROR13(const char *str);
DWORD str_hash_ROR13_w(const wchar_t* str);
wchar_t* str_wcsrchr(const wchar_t* str, wchar_t ch);
#endif