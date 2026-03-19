#include <stdio.h>
#include <windows.h>
#include "strutils.h"

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        printf("Usage:\n");
        printf("  %s -a <string>   (ANSI)\n", argv[0]);
        printf("  %s -w <string>   (WIDE)\n", argv[0]);
        return 1;
    }

    char *flag = argv[1];
    char *input = argv[2];

    if (flag[0] == '-' && flag[1] == 'a')
    {
        DWORD hash = str_hash_ROR13(input);
        printf("[ANSI] \"%s\" -> 0x%08X\n", input, hash);
    }
    else if (flag[0] == '-' && flag[1] == 'w')
    {
        // conversione ANSI → wide
        wchar_t wbuf[512];
        MultiByteToWideChar(CP_ACP, 0, input, -1, wbuf, 512);

        DWORD hash = str_hash_ROR13_w(wbuf);
        printf("[WIDE] \"%s\" -> 0x%08X\n", input, hash);
    }
    else
    {
        printf("Invalid flag. Use -a or -w\n");
        return 1;
    }

    return 0;
}