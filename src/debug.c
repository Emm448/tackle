#include "debug.h"

void debug_pe_print_imports(PE* pe)
{
    if (!pe)
        return;

    IMAGE_IMPORT_DESCRIPTOR* import = pe_get_imports(pe);
    if (!import)
        return;

    for (; import->Name; import++)
    {
        char* dllName = (char*)pe_rva_to_ptr(pe, import->Name);

        if (dllName)
        {
            printf("[IMPORT] %s\n", dllName);
        }
    }
}

void debug_pe_print_imported_functions(PE* pe)
{
    if (!pe)
        return;

    IMAGE_IMPORT_DESCRIPTOR* imp = pe_get_imports(pe);
    if (!imp)
        return;

    for (; imp->Name; imp++)
    {
        char* dllName = (char*)pe_rva_to_ptr(pe, imp->Name);
        if (!dllName)
            continue;

        printf("\n[DLL] %s\n", dllName);

        IMAGE_THUNK_DATA* oft = pe_rva_to_ptr(pe, imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA* ft  = pe_rva_to_ptr(pe, imp->FirstThunk);

        if (!oft)
            oft = ft;

        if (!ft)
            continue;

        for (; oft->u1.AddressOfData; oft++, ft++)
        {
            if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal))
            {
                printf("  [ORDINAL] #%llu\n", oft->u1.Ordinal);
                continue;
            }

            IMAGE_IMPORT_BY_NAME* ibn =
                pe_rva_to_ptr(pe, oft->u1.AddressOfData);

            if (!ibn)
                continue;

            printf("  %s\n", ibn->Name);
        }
    }
}