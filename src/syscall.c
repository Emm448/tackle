#include "pe.h"
#include "peb.h"
#include "syscall.h"

#define STUB_SIZE 32

void* _syscall_build_stub(DWORD syscall_number)
{	
	// Values XORed with 0xFF (original stub bytes obfuscated)
	unsigned char syscall_stub[] = {
		0xB3, 0x74, 0x2E,             // mov r10, rcx
		0x47, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, syscall_number 
		0xF0, 0xFA,                   // syscall 
		0x3C                          // ret 
	};

	//Deobfuscating stub
	for(int i = 0; i < 11; i++)
		syscall_stub[i] = 0xFF ^ syscall_stub[i] ; 
	//--
	
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
    BYTE* stub = (BYTE*)func;

    // Deobfuscating {0x4C, 0x8B, 0xD1, 0xB8} pattern
    BYTE pattern[4] = {0xB3, 0x74, 0x2E, 0x47};
	
	for (int i = 0; i < 4; i++)
        pattern[i] = 0xFF ^ pattern[i];
	//---
	
	//Searching pattern
    for (int i = 0; i < STUB_SIZE - 4; i++)
    {
        if (stub[i]	  == pattern[0] &&
            stub[i+1] == pattern[1] &&
            stub[i+2] == pattern[2] &&
            stub[i+3] == pattern[3])
        {
            return *(DWORD*)(stub + i + 4);
        }

        if (stub[i] == 0xc3) return 0;
        if (stub[i] == 0xe9) return 0;
    }
	
    return 0;
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
	
	//Deobfuscating {0x4C, 0x8B, 0xD1, 0xB8} pattern
	BYTE pattern[4] = {0xB3, 0x74, 0x2E, 0x47};
	
	int i;
	for(i = 0; i < 4; i++)
		pattern[i] = 0xFF ^ pattern[i] ; 
	//--
	
	for (int i = 0; i < 64; i++){
		if (p[i]     == pattern[0] &&	//0x4C
			p[i + 1] == pattern[1] &&	//0x8B
			p[i + 2] == pattern[2] &&	//0xD1 (mov r10, rcx)
			p[i + 3] == pattern[3])		//0xB8 (mov eax, syscall_number)
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

void* _find_syscall_gate(void* func)
{	
	BYTE* stub = (BYTE*)func;
    for (int i = 0; i < STUB_SIZE; i++)
    {
        if (stub[i] == 0x0f &&
            stub[i+1] == 0x05 &&
            stub[i+2] == 0xc3)
        {
            return (stub + i);
        }
    }
    return NULL;
}

SYSCALL_INFO syscall_resolve_indirect_hash(DWORD funcHash)
{
	SYSCALL_INFO info = {0};
	
    // PEB walking to rietrieving ntdll
    PPEB peb = peb_get();
    if (!peb)
        return info;

    HMODULE ntdll = peb_get_module_hash(peb, HASH_NTDLL);
    if (!ntdll)
        return info;
	//---
	
    // PE parsing
    PE pe;
    if (!pe_init(&pe, ntdll, TRUE))
        return info;

    void* func = pe_find_export_hash(&pe, funcHash);
    if (!func)
        return info;
	//---
	
    
	void* stub = func;
    PVOID gate = NULL;
	DWORD ssn = _syscall_get_number(stub);
	
    if (!ssn)
    {
		//Halo's Gate
        for (int i = 1; i < 500; i++)
        {
            if (_syscall_get_number(stub + (i * STUB_SIZE)))
            {
                ssn -= i;
                stub = stub + (i * STUB_SIZE);
                break;
            }

            if (_syscall_get_number(stub - (i * STUB_SIZE)))
            {
                ssn += i;
                stub = stub - (i * STUB_SIZE);
                break;
            }
        }
    }

    if (!ssn)
        return info;

    gate = _find_syscall_gate(stub);
    if (!gate)
        return info;

    info.syscall_id = ssn;
    info.syscall_addr = gate;

    return info;
}

void* syscall_build_indirect_stub(DWORD funcHash)
{
	// Values XORed with 0xFF (original stub bytes obfuscated)
	unsigned char stub[] = {
		// mov r10, rcx
		0xB3, 0x74, 0x2E,
		// mov eax, syscall_id
		0x47, 0xFF,0xFF,0xFF,0xFF,
		//gate x64
		0x00, 0xDA, 0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF
	};
	
	//Deobfuscating stub
	for(int i = 0; i < 22; i++)
		stub[i] = 0xFF ^ stub[i] ; 
	//--
	
	SYSCALL_INFO s = syscall_resolve_indirect_hash(funcHash);
	if(s.syscall_id == 0 || s.syscall_addr == 0)
		return NULL;
	
	//Avoiding RWX memory allocation
	BYTE* mem = VirtualAlloc(
		NULL,
		sizeof(stub),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	memcpy(mem, stub, sizeof(stub));

	// Patch syscall
	*(DWORD*)(mem + 4) = s.syscall_id;
    *(void**)(mem + 14) = s.syscall_addr;

	// Change protection to RX
	DWORD old;
	VirtualProtect(mem, sizeof(stub), PAGE_EXECUTE_READ, &old);

    return mem;
}