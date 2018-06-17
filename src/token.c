#include <stdio.h>
#include <Windows.h>
#include <Sddl.h>
#include "token.h"
#include "utils.h"

void printResolvedSID(PSID pSID, BOOL bPrintDomain)
{
    PWSTR pwzUsername = NULL;
    DWORD dwUsernameLen = 0;
    PWSTR pwzDomain = NULL;
    DWORD dwDomainLen = 0;
    SID_NAME_USE sidUse;

    if (LookupAccountSidW(NULL, pSID, pwzUsername, &dwUsernameLen, pwzDomain, &dwDomainLen, &sidUse) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        printf("unable to resolve, error %u", GetLastError());
    }
    else
    {
        pwzUsername = safe_alloc(dwUsernameLen * sizeof(WCHAR));
        pwzDomain = safe_alloc(dwDomainLen * sizeof(WCHAR));
        if (!LookupAccountSidW(NULL, pSID, pwzUsername, &dwUsernameLen, pwzDomain, &dwDomainLen, &sidUse))
        {
            printf("unable to resolve, error %u", GetLastError());
        }
        else if (bPrintDomain)
        {
            wprintf(L"%s\\%s", pwzDomain, pwzUsername);
        }
        else
        {
            wprintf(L"%s", pwzUsername);
        }
        safe_free(pwzDomain);
        safe_free(pwzUsername);
    }
}

void printSID(PSID pSID, BOOL bResolve)
{
    PSTR pStringSid = NULL;
    if (!ConvertSidToStringSidA(pSID, &pStringSid))
    {
        fprintf(stderr, "unable to convert sid, error %u", GetLastError());
        fflush(stderr);
    }
    else
    {
        printf("%s", pStringSid);
        LocalFree(pStringSid);
        if (bResolve)
        {
            printf(" (");
            printResolvedSID(pSID, TRUE);
            printf(")");
        }
    }
}

BOOL getTokenInfo(HANDLE hToken, TOKEN_INFORMATION_CLASS type, PVOID *ppBuffer, DWORD *pdwBufLen)
{
    int res;
    DWORD dwOutLen = 0;

    do
    {
        res = 0;
        if (!GetTokenInformation(hToken, type, *ppBuffer, *pdwBufLen, &dwOutLen))
        {
            res = GetLastError();
            if (res == ERROR_INSUFFICIENT_BUFFER)
            {
                *pdwBufLen *= 2;
                *ppBuffer = safe_realloc(*ppBuffer, *pdwBufLen);
            }
            else
            {
                fprintf(stderr, " [!] Unable to query GetTokenInformation(%u), code %u\n", type, res);
            }
        }
    } while (res == ERROR_INSUFFICIENT_BUFFER);

    return (res == 0);
}


void printToken(HANDLE hToken)
{
    DWORD dwTokInfoLen = 200;
    PVOID pTokInfo = safe_alloc(dwTokInfoLen);

    if (getTokenInfo(hToken, TokenType, &pTokInfo, &dwTokInfoLen))
    {
        if (*(PTOKEN_TYPE)pTokInfo == TokenPrimary)
        {
            printf("     Primary token\n");
        }
        else
        {
            PCSTR pzLevel = "unknown";
            if (getTokenInfo(hToken, TokenImpersonationLevel, &pTokInfo, &dwTokInfoLen))
            {
                switch (*(PSECURITY_IMPERSONATION_LEVEL)pTokInfo)
                {
                case SecurityAnonymous:
                    pzLevel = "anonymous";
                    break;
                case SecurityIdentification:
                    pzLevel = "identification";
                    break;
                case SecurityImpersonation:
                    pzLevel = "impersonation";
                    break;
                case SecurityDelegation:
                    pzLevel = "delegation";
                    break;
                }
            }
            printf("     Impersonation token (%s level)\n", pzLevel);
        }
    }
    if (getTokenInfo(hToken, TokenSessionId, &pTokInfo, &dwTokInfoLen))
    {
        printf("     Session ID: 0x%X\n", *(PDWORD)pTokInfo);
    }
    if (getTokenInfo(hToken, TokenUser, &pTokInfo, &dwTokInfoLen))
    {
        PTOKEN_USER pUser = (PTOKEN_USER)pTokInfo;
        printf("     User:   ");
        printSID(pUser->User.Sid, TRUE);
        printf("\n");
    }
    if (getTokenInfo(hToken, TokenGroups, &pTokInfo, &dwTokInfoLen))
    {
        PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)pTokInfo;
        BOOL bFound = FALSE;
        printf("     Enabled SIDs:\n");
        for (DWORD i = 0; i < pGroups->GroupCount; i++)
        {
            if (!flagsSet(pGroups->Groups[i].Attributes, SE_GROUP_ENABLED))
                continue;
            if (!bFound)
                bFound = TRUE;
            printf("             ");
            printSID(pGroups->Groups[i].Sid, TRUE);
            if (flagsSet(pGroups->Groups[i].Attributes, SE_GROUP_MANDATORY))
                printf(" (mandatory)");
            printf("\n");
        }
        if (!bFound)
            printf("             none");
        bFound = FALSE;
        printf("     Deny-only SIDs:\n");
        for (DWORD i = 0; i < pGroups->GroupCount; i++)
        {
            if (!flagsSet(pGroups->Groups[i].Attributes, SE_GROUP_USE_FOR_DENY_ONLY))
                continue;
            bFound = TRUE;
            printf("             ");
            printSID(pGroups->Groups[i].Sid, TRUE);
            printf("\n");
            break;
        }
        if (!bFound)
            printf("             none\n");
    }
    if (getTokenInfo(hToken, TokenRestrictedSids, &pTokInfo, &dwTokInfoLen))
    {
        PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)pTokInfo;
        BOOL bFound = FALSE;
        printf("     Restricted SIDs:\n");
        for (DWORD i = 0; i < pGroups->GroupCount; i++)
        {
            if (!flagsSet(pGroups->Groups[i].Attributes, SE_GROUP_ENABLED))
                continue;
            bFound = TRUE;
            printf("             ");
            printSID(pGroups->Groups[i].Sid, TRUE);
            printf("\n");
            break;
        }
        if (!bFound)
            printf("             none\n");
    }
    if (getTokenInfo(hToken, TokenPrivileges, &pTokInfo, &dwTokInfoLen))
    {
        PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)pTokInfo;
        DWORD dwPrivNameLen = 0;
        PSTR pzPrivName = NULL;
        BOOL bFound = FALSE;
        printf("     Privileges:\n");
        for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++)
        {
            bFound = TRUE;
            dwPrivNameLen = 0;
            if (LookupPrivilegeNameA(NULL, &(pPrivs->Privileges[i].Luid), pzPrivName, &dwPrivNameLen) ||
                GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                fprintf(stderr, " [!] Unable to query LookupPrivilegeName(), code %u\n", GetLastError());
                continue;
            }
            pzPrivName = safe_alloc(dwPrivNameLen);
            if (!LookupPrivilegeNameA(NULL, &(pPrivs->Privileges[i].Luid), pzPrivName, &dwPrivNameLen))
            {
                fprintf(stderr, " [!] Unable to query LookupPrivilegeName(), code %u\n", GetLastError());
                continue;
            }
            printf("             %s\n", pzPrivName);
            safe_free(pzPrivName);
        }
    }
    if (getTokenInfo(hToken, TokenMandatoryPolicy, &pTokInfo, &dwTokInfoLen))
    {
        PTOKEN_MANDATORY_POLICY pPolicy = (PTOKEN_MANDATORY_POLICY)pTokInfo;
        BOOL bFound = FALSE;
        printf("     Mandatory policy:\n");
        if (flagsSet(pPolicy->Policy, TOKEN_MANDATORY_POLICY_NO_WRITE_UP))
        {
            printf("             NO_WRITE_UP\n");
            bFound = TRUE;
        }
        if (flagsSet(pPolicy->Policy, TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN))
        {
            printf("             NEW_PROCESS_MIN\n");
            bFound = TRUE;
        }
        if (!bFound)
            printf("             none\n");
    }
    if (getTokenInfo(hToken, TokenAccessInformation, &pTokInfo, &dwTokInfoLen))
    {
        PTOKEN_ACCESS_INFORMATION pAccess = (PTOKEN_ACCESS_INFORMATION)pTokInfo;
        printf("     Protected process trust: ");
        if (pAccess->TrustLevelSid == NULL)
            printf("none");
        else
            printSID(pAccess->TrustLevelSid, TRUE);
        printf("\n");
    }
    //if (getTokenInfo(hToken, TokenSandBoxInert, &pTokInfo, &dwTokInfoLen))
}