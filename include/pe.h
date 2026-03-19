#ifndef PE_H
#define PE_H

#include <windows.h>

typedef struct PE
{
    void* base;
	
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS* nt;
    IMAGE_FILE_HEADER* file;

    void* optional;

    IMAGE_SECTION_HEADER* sections;

    BOOL is64;
	BOOL mapped;

} PE; 


//--------------------------------------------------
// HELPERS
//--------------------------------------------------

void* pe_rva_to_ptr(PE* pe, DWORD rva);

//--------------------------------------------------
// PE CORE
//--------------------------------------------------

BOOL pe_init(PE* pe, void* base, BOOL mapped);

PIMAGE_DATA_DIRECTORY pe_get_directory(PE* pe, DWORD index);
PIMAGE_IMPORT_DESCRIPTOR pe_get_imports(PE* pe);
IMAGE_IMPORT_DESCRIPTOR* pe_find_dll(PE* pe, const char* dll);
IMAGE_IMPORT_DESCRIPTOR* pe_find_dll_hash(PE* pe, DWORD hash);
void** pe_find_function(PE* pe, const char* dllName, const char* funcName);
void** pe_find_function_hash(PE* pe, DWORD dllHash, DWORD funcHash);
void* pe_find_export(PE* pe, const char* name);
void* pe_find_export_hash(PE* pe, DWORD hash);
#endif