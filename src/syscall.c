#include "pe.h"
#include "peb.h"
#include "syscall.h"

void* _syscall_build_stub(DWORD syscall_number) {
	unsigned char syscall_stub[] = {
		0x4C, 0x8B, 0xD1,             // mov r10, rcx
		0xB8, 0, 0, 0, 0,             // mov eax, syscall_number
		0x0F, 0x05,                   // syscall
		0xC3                          // ret
	};

	//Avoiding RWX memory allocation
	void* mem = VirtualAlloc(
		NULL,
		sizeof(syscall_stub),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	memcpy(mem, syscall_stub, sizeof(syscall_stub));

	// Patch syscall
	*(DWORD*)((BYTE*)mem + 4) = syscall_number;

	// Change protection to RX
	DWORD old;
	VirtualProtect(mem, sizeof(syscall_stub), PAGE_EXECUTE_READ, &old);

    return mem;
}

DWORD _syscall_get_number(void* func)
{
    BYTE* p = (BYTE*)func;

    // Check base pattern
    if (p[0] != 0x4C || p[1] != 0x8B || p[2] != 0xD1)
        return 0;

    if (p[3] != 0xB8)
        return 0;

    return *(DWORD*)(p + 4);
}


void* syscall_build_stub_hash(DWORD funcHash)
{
	//PEB walking to rietrieving ntdll
	PPEB peb = peb_get();
	if(!peb)
		return NULL;
	
	HMODULE ntdll = peb_get_module_hash(peb, HASH_NTDLL);
	if(!ntdll)
		return NULL;
	//---
	
	//PE parsing to find the function
	PE pe;
	if(!pe_init(&pe, ntdll, TRUE))
		return NULL;
	
	void* func = pe_find_export_hash(&pe, funcHash);
	if(!func)
		return NULL;
	//---
	
    DWORD syscall_number = _syscall_get_number(func);
	return _syscall_build_stub(syscall_number);
}

void* syscall_resolve_stub_hash(DWORD funcHash)
{
    // PEB walking to rietrieving ntdll
    PPEB peb = peb_get();
    if (!peb)
        return NULL;

    HMODULE ntdll = peb_get_module_hash(peb, HASH_NTDLL);
    if (!ntdll)
        return NULL;
	//---
	
    // PE parsing
    PE pe;
    if (!pe_init(&pe, ntdll, TRUE))
        return NULL;

    void* func = pe_find_export_hash(&pe, funcHash);
    if (!func)
        return NULL;
	//---
	
    BYTE* p = (BYTE*)func;
	   
	for (int i = 0; i < 64; i++){
		if (p[i]     == 0x4C &&
			p[i + 1] == 0x8B &&
			p[i + 2] == 0xD1 &&		//mov r10, rcx
			p[i + 3] == 0xB8)		//mov eax, syscall_number
		{
			//Searching for "syscall" instruction
			for (int j = i + 4; j < i + 32; j++){
				if (p[j] == 0x0F && p[j + 1] == 0x05){
					return (void*)(p + i);
				}
			}
		}
	}

    return NULL;
}