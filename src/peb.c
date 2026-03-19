#include "peb.h"
#include "strutils.h"

PPEB peb_get()
{
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

wchar_t* get_basename(wchar_t* full)
{
    wchar_t* p1 = str_wcsrchr(full, L'\\');
    wchar_t* p2 = str_wcsrchr(full, L'/');

    wchar_t* p = (p1 > p2) ? p1 : p2;

    return p ? (p + 1) : full;
}

HMODULE peb_get_module_hash(PPEB peb, DWORD hash)
{
    if (!peb || !peb->Ldr)
        return NULL;

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current = head->Flink;

    while (current != head)
    {
        LDR_DATA_TABLE_ENTRY* entry =
            CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        wchar_t* dll_name = entry->FullDllName.Buffer;

        if (dll_name)
        {
            wchar_t* base = get_basename(dll_name);
			
            if (base && str_hash_ROR13_w(base) == hash)
			{
                return (HMODULE)entry->DllBase;
			}
        }

        current = current->Flink;
    }

    return NULL;
}
