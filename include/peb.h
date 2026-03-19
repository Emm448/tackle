#ifndef PEB_H
#define PEB_H

#include <winternl.h>

PPEB peb_get();
HMODULE peb_get_module_hash(PPEB peb, DWORD hash);

#endif