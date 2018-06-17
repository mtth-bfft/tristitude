#pragma once
#include <Windows.h>

void printResolvedSID(PSID pSID, BOOL bPrintDomain);
void printSID(PSID pSID, BOOL bResolve);
BOOL getTokenInfo(HANDLE hToken, TOKEN_INFORMATION_CLASS type, PVOID *ppBuffer, DWORD *pdwBufLen);
void printToken(HANDLE hToken);