#ifndef SYSCALL_H
#define SYSCALL_H

#define HASH_NTDLL 0xCEF6E822
#include <windows.h>

//direct syscall
void* syscall_build_stub_hash(DWORD funcHash);
void* syscall_resolve_stub_hash(DWORD funcHash);


//indirect syscall
typedef struct {
    void* syscall_addr;
    DWORD syscall_id;
} SYSCALL_INFO;

void* syscall_build_indirect_stub(DWORD funcHash);

#endif


