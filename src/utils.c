#include <stdio.h>
#include "utils.h"

PVOID safe_alloc(DWORD dwBytes)
{
    PVOID res = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytes);
    if (res == NULL)
    {
        fprintf(stderr, " [!] Out of memory\n");
        exit(ERROR_OUTOFMEMORY);
    }
    return res;
}

PVOID safe_realloc(PVOID pOld, DWORD dwBytes)
{
    PVOID res = HeapReAlloc(GetProcessHeap(), 0, pOld, dwBytes);
    if (res == NULL)
    {
        fprintf(stderr, " [!] Out of memory\n");
        exit(ERROR_OUTOFMEMORY);
    }
    return res;
}

VOID safe_free(PVOID pBuf)
{
    HeapFree(GetProcessHeap(), 0, pBuf);
}

PCSTR prettifySize(double bytes)
{
    static char buf[255] = { 0 };
    int unit = 0;
    const char* units[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };
    while (bytes > 1024) {
        bytes /= 1024;
        unit++;
    }
    snprintf(buf, sizeof(buf), "%.*f %s", unit, bytes, units[unit]);
    return buf;
}
