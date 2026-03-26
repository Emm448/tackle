#include <stdio.h>
#include "syscall.h"

//--------------------------------------------------
// ROR13 HASHES
//--------------------------------------------------
#define HASH_NtAllocateVirtualMemory 0xD33BCD4F

//--------------------------------------------------
// Original NtAllocateVirtualMemory definition
//--------------------------------------------------
typedef NTSTATUS (*NtAllocateVirtualMemory_t)(
    HANDLE,
    PVOID*,
    ULONG_PTR,
    PSIZE_T,
    ULONG,
    ULONG
);

/*
 * <Alternative approach>
 * void* syscall_build_stub_hash(DWORD funcHash) resolves the syscall
 * number and builds a custom executable stub in dynamically allocated 
 * memory.
 *
 * This method is reliable but less stealthy, as it typically relies
 * on VirtualAlloc and RW -> RX memory transitions, which are commonly
 * monitored by EDR solutions.
 *
 * In this example we use void* syscall_resolve_stub_hash(DWORD funcHash)
 * which instead reuses the existing syscall stub from ntdll, avoiding
 * new executable memory allocations and reducing the detection surface.
 */

int main() {
    printf("[*] Building syscall stub...\n");

	void* stub = syscall_resolve_stub_hash(HASH_NtAllocateVirtualMemory);
    if (!stub) {
        printf("[-] Failed to resolve syscall stub\n");
        return -1;
    }

    printf("[+] Stub at: %p\n", stub);

    NtAllocateVirtualMemory_t NtAlloc =
        (NtAllocateVirtualMemory_t)stub;

    PVOID base = NULL;
    SIZE_T size = 0x1000;

    printf("[*] Invoking NtAllocateVirtualMemory...\n");

    NTSTATUS status = NtAlloc(
        GetCurrentProcess(),
        &base,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    printf("[+] NTSTATUS: 0x%08X\n", status);

    if (status == 0) {
        printf("[+] Allocation successful\n");
        printf("\t-> BaseAddress: %p\n", base);
        printf("\t-> Size: 0x%zx\n", size);

        // Write test
        memset(base, 0x41, size);
        printf("[+] Memory test OK (first byte = 0x%02X)\n",
               ((unsigned char*)base)[0]);
    } else {
        printf("[-] Allocation failed\n");
    }

    return 0;
}