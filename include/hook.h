#ifndef HOOK_H
#define HOOK_H

#include <windows.h>

BOOL hook_iat(void** entry, void* hook, void** original);
#endif