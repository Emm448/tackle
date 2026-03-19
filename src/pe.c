#include "pe.h"
#include "strutils.h"

BOOL pe_init(PE* pe, void* base, BOOL mapped)
{
    if (!pe || !base)
        return FALSE;

    pe->base = base;

    // PE starts IMAGE_DOS_HEADER
    pe->dos = (IMAGE_DOS_HEADER*)base;

    // Check DOS signature ("MZ")
    if (pe->dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    // Get NT header from e_lfanew offset 
    // e_lfanew point to the start of structure "PE\0\0"
    pe->nt = (IMAGE_NT_HEADERS*)((BYTE*)base + pe->dos->e_lfanew);

    // Check PE signature ("PE\0\0")
    if (pe->nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // Pointer to FILE_HEADER
    pe->file = &pe->nt->FileHeader;

    // can be IMAGE_OPTIONAL_HEADER32 or IMAGE_OPTIONAL_HEADER64
    pe->optional = &pe->nt->OptionalHeader;

    // Pointer PE next section
    pe->sections = IMAGE_FIRST_SECTION(pe->nt);

    pe->is64 = (pe->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
	
	pe->mapped = mapped;
	
    return TRUE;
}

PIMAGE_DATA_DIRECTORY pe_get_directory(PE* pe, DWORD index)
{
    if (!pe)
        return NULL;

    if (index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return NULL;

    PIMAGE_DATA_DIRECTORY dir = &((PIMAGE_OPTIONAL_HEADER)pe->optional)->DataDirectory[index];

	// If directory does not exists VirtualAddress is set to 0
    if (!dir->VirtualAddress)
        return NULL;

    return dir;
}

void* pe_rva_to_ptr(PE* pe, DWORD rva)
{
    if (!pe || !rva)
        return NULL;

    // PE already in memory
    if (pe->mapped)
        return (BYTE*)pe->base + rva;

    // PE on disk
    for (WORD i = 0; i < pe->file->NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER* sec = &pe->sections[i];

        DWORD start = sec->VirtualAddress;
        DWORD end   = start + sec->Misc.VirtualSize;

        if (rva >= start && rva < end)
        {
            DWORD offset = rva - start;
            return (BYTE*)pe->base + sec->PointerToRawData + offset;
        }
    }

    return NULL;
}

PIMAGE_IMPORT_DESCRIPTOR pe_get_imports(PE* pe)
{
    if (!pe)
        return NULL;

    PIMAGE_DATA_DIRECTORY dir = pe_get_directory(pe, IMAGE_DIRECTORY_ENTRY_IMPORT);

    if (!dir)
        return NULL;

    return (PIMAGE_IMPORT_DESCRIPTOR) pe_rva_to_ptr(pe, dir->VirtualAddress);
}

IMAGE_IMPORT_DESCRIPTOR* pe_find_dll(PE* pe, const char* dll)
{
    if (!pe)
        return NULL;

    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = pe_get_imports(pe);

    if (!importDescriptor)
        return NULL;

    for (; importDescriptor->Name; importDescriptor++)
    {
        char* dllName = (char*)pe_rva_to_ptr(pe, importDescriptor->Name);
        if(str_cmp(dllName, dll) == 0)
			return importDescriptor;
    }

	return NULL;
}

IMAGE_IMPORT_DESCRIPTOR* pe_find_dll_hash(PE* pe, DWORD hash)
{
    if (!pe)
        return NULL;

    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = pe_get_imports(pe);

    if (!importDescriptor)
        return NULL;

    for (; importDescriptor->Name; importDescriptor++)
    {
        char* dllName = (char*)pe_rva_to_ptr(pe, importDescriptor->Name);
        if(str_hash_ROR13(dllName) == hash)
			return importDescriptor;
    }

	return NULL;
}

void** pe_find_function(PE* pe, const char* dllName, const char* funcName)
{
    IMAGE_IMPORT_DESCRIPTOR* imp = pe_find_dll(pe, dllName);
	if (!imp)
		return NULL;

	IMAGE_THUNK_DATA* oft = pe_rva_to_ptr(pe, imp->OriginalFirstThunk);
	IMAGE_THUNK_DATA* ft  = pe_rva_to_ptr(pe, imp->FirstThunk);

	if (!oft)
		oft = ft;
	
	if (!ft)
		return NULL;

	for (; oft->u1.AddressOfData; oft++, ft++)
	{
		if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal))
			continue;

		IMAGE_IMPORT_BY_NAME* ibn =
			pe_rva_to_ptr(pe, oft->u1.AddressOfData);
		
		if (!ibn)
			return NULL;
	
		if (str_cmp(ibn->Name, funcName) == 0)
		{
			return (void**)&ft->u1.Function;
		}
	}

    return NULL;
}

void** pe_find_function_hash(PE* pe, DWORD dllHash, DWORD funcHash)
{
	IMAGE_IMPORT_DESCRIPTOR* imp = pe_find_dll_hash(pe, dllHash);
	if (!imp)
		return NULL;

	IMAGE_THUNK_DATA* oft = pe_rva_to_ptr(pe, imp->OriginalFirstThunk);
	IMAGE_THUNK_DATA* ft  = pe_rva_to_ptr(pe, imp->FirstThunk);

	if (!oft)
		oft = ft;
	
	if (!ft)
		return NULL;

	for (; oft->u1.AddressOfData; oft++, ft++)
	{
		if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal))
			continue;

		IMAGE_IMPORT_BY_NAME* ibn =
			pe_rva_to_ptr(pe, oft->u1.AddressOfData);
		
		if (!ibn)
			return NULL;
	
		if (str_hash_ROR13(ibn->Name) == funcHash)
		{
			return (void**)&ft->u1.Function;
		}
	}

    return NULL;	
}

void* pe_find_export(PE* pe, const char* name)
{
    if (!pe || !name)
        return NULL;

    IMAGE_DATA_DIRECTORY* dir =
        pe_get_directory(pe, IMAGE_DIRECTORY_ENTRY_EXPORT);

    if (!dir || !dir->VirtualAddress)
        return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)
        pe_rva_to_ptr(pe, dir->VirtualAddress);

    if (!exp)
        return NULL;

    DWORD* names = (DWORD*)pe_rva_to_ptr(pe, exp->AddressOfNames);
    WORD* ordinals = (WORD*)pe_rva_to_ptr(pe, exp->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)pe_rva_to_ptr(pe, exp->AddressOfFunctions);

    if (!names || !ordinals || !functions)
        return NULL;

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        char* funcName = (char*)pe_rva_to_ptr(pe, names[i]);

        if (!funcName)
            continue;

        if (str_cmp(funcName, name) == 0)
        {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];

            return pe_rva_to_ptr(pe, funcRVA);
        }
    }

    return NULL;
}

void* pe_find_export_hash(PE* pe, DWORD hash)
{
    if (!pe || !hash)
        return NULL;

    IMAGE_DATA_DIRECTORY* dir =
        pe_get_directory(pe, IMAGE_DIRECTORY_ENTRY_EXPORT);

    if (!dir || !dir->VirtualAddress)
        return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)
        pe_rva_to_ptr(pe, dir->VirtualAddress);

    if (!exp)
        return NULL;

    DWORD* names = (DWORD*)pe_rva_to_ptr(pe, exp->AddressOfNames);
    WORD* ordinals = (WORD*)pe_rva_to_ptr(pe, exp->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)pe_rva_to_ptr(pe, exp->AddressOfFunctions);

    if (!names || !ordinals || !functions)
        return NULL;

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        char* funcName = (char*)pe_rva_to_ptr(pe, names[i]);

        if (!funcName)
            continue;

        if (str_hash_ROR13(funcName) == hash)
        {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];

            return pe_rva_to_ptr(pe, funcRVA);
        }
    }

    return NULL;	
}