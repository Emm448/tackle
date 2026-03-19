#include "hook.h"

BOOL hook_iat(void** entry, void* hook, void** original)
{
	if (!entry)
		return FALSE;

	if (original)
		*original = *entry;

	DWORD oldProtect;

	if (!VirtualProtect(entry, sizeof(void*), PAGE_READWRITE, &oldProtect))
		return FALSE;

	*entry = hook;

	VirtualProtect(entry, sizeof(void*), oldProtect, &oldProtect);

	return TRUE;
}