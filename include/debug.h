#ifndef DEBUG_H
#define DEBUG_H

#include "pe.h"
#include <stdio.h>

void debug_pe_print_imports(PE* pe);
void debug_pe_print_imported_functions(PE* pe);
#endif