#ifndef SYSCALL_H
#define SYSCALL_H

#define HASH_NTDLL 0xCEF6E822
#include <windows.h>

void* syscall_build_stub_hash(DWORD funcHash);
void* syscall_resolve_stub_hash(DWORD funcHash);

#endif


