#include "pe.h"
#include "hook.h"

//--------------------------------------------------
// ROR13 HASHES
//--------------------------------------------------
#define HASH_USER32			0x542EEE26
#define HASH_MESSAGEBOXA	0xFC4DA2D0

//--------------------------------------------------
// Original MessageBoxA definition
//--------------------------------------------------
typedef int (WINAPI* MessageBoxA_t)(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType
);

MessageBoxA_t original_MessageBoxA = NULL;

int WINAPI hook_MessageBoxA(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType
)
{
    return original_MessageBoxA(
        hWnd,
        "HOOKED :)",
        lpCaption,
        uType
    );
}

int main()
{	
    PE pe;
	pe_init(&pe, GetModuleHandle(NULL), TRUE);

	void** entry = pe_find_function_hash(&pe, HASH_USER32, HASH_MESSAGEBOXA);
	
	// IAT hook failed: DLL/function not in IAT or patching failed :(
    if (!hook_iat(entry, hook_MessageBoxA, (void**)&original_MessageBoxA))
		return -1;
	
    MessageBoxA(NULL, "Original", "Test", MB_OK);

    return 0;
}