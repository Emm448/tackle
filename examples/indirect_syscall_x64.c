#include <stdio.h>
#include "syscall.h"

//--------------------------------------------------
// ROR13 HASHES
//--------------------------------------------------
#define HASH_NtAllocateVirtualMemory 0xD33BCD4F

//--------------------------------------------------
// Original NtAllocateVirtualMemory definition
//--------------------------------------------------
typedef NTSTATUS (NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

int main()
{
    void* stub = syscall_build_indirect_stub(HASH_NtAllocateVirtualMemory);

    if (!stub)
    {
        printf("[-] stub allocation failed\n");
        return -1;
    }

	printf("[+] Stub at: %p\n", stub);
 
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory_sys =
        (NtAllocateVirtualMemory_t)stub;

    PVOID base = NULL;
    SIZE_T size = 0x1000;

    printf("[*] Invoking indirect syscall...\n");

    NTSTATUS status = NtAllocateVirtualMemory_sys(
        (HANDLE)-1,
        &base,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    printf("[+] NTSTATUS: 0x%08X\n", status);

    if (status == 0)
    {
        printf("[+] Allocation successful\n");
        printf("\t-> BaseAddress: %p\n", base);
        printf("\t-> Size: 0x%zx\n", size);

        memset(base, 0x41, size);

        printf("[+] Memory test OK (first byte = 0x%02X)\n",
               ((unsigned char*)base)[0]);
    }
    else
    {
        printf("[-] Allocation failed\n");
    }

    return 0;
}