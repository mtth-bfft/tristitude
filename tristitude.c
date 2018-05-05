#include <stdio.h>
#include <Windows.h>
#include <Sddl.h>

#define flagsSet(val,flags) (((val) & (flags)) == (flags))

// Optional functions & typedefs imported only when the OS supports them

#define SystemHandleInformation 16
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_NOT_SUPPORTED 0xC00000BB
#define STATUS_ACCESS_DENIED 0xC0000022
#define NT_SUCCESS(x) ((x) >= 0)

typedef enum {
    ObjectBasicInformation = 0,
    ObjectNameInformation,
    ObjectTypeInformation,
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved[22];
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS(NTAPI *_NtQueryObject)(
    HANDLE ObjectHandle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

static _NtQuerySystemInformation pNtQuerySystemInformation = NULL;
static _NtDuplicateObject pNtDuplicateObject = NULL;
static _NtQueryObject pNtQueryObject = NULL;

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

BOOL getProcessJob(HANDLE hProcess, HANDLE *phJob)
{
    NTSTATUS status = 0;
    DWORD dwPid = GetProcessId(hProcess);
    ULONG ulHandlesSize = 0x2000;
    PSYSTEM_HANDLE_INFORMATION pHandles = safe_alloc(ulHandlesSize);
    ULONG ulObjTypeSize = 0x1000;
    PPUBLIC_OBJECT_TYPE_INFORMATION pObjType = safe_alloc(ulObjTypeSize);
    BOOL bFound = FALSE;

    if (pNtQuerySystemInformation == NULL ||
        pNtDuplicateObject == NULL ||
        pNtQueryObject == NULL)
    {
        return FALSE;
    }

    while ((status = pNtQuerySystemInformation(SystemHandleInformation,
        pHandles, ulHandlesSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        ulHandlesSize *= 2;
        pHandles = (PSYSTEM_HANDLE_INFORMATION)safe_realloc(pHandles, ulHandlesSize);
    }
    if (!NT_SUCCESS(status))
    {
        fprintf(stderr, " [!] NtQuerySystemInformation(): status 0x%08X\n", status);
        safe_free(pHandles);
        return FALSE;
    }

    for (ULONG i = 0; i < pHandles->HandleCount; i++)
    {
        SYSTEM_HANDLE handle = pHandles->Handles[i];
        HANDLE hJob = NULL;
        HANDLE hOtherProc = NULL;
        if (handle.GrantedAccess == 0x0012019f) // NtQueryObject() can hang on objects with such access rights
            continue;
        hOtherProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);
        if (hOtherProc == NULL)
        {
            if (GetLastError() != ERROR_ACCESS_DENIED && GetLastError() != ERROR_INVALID_PARAMETER)
                fprintf(stderr, " [!] OpenProcess(PROCESS_DUP_HANDLE, %u), code %u\n", handle.ProcessId, GetLastError());
            continue;
        }
        status = pNtDuplicateObject(hOtherProc, (HANDLE)(int)handle.Handle, GetCurrentProcess(), &hJob, JOB_OBJECT_QUERY, 0, 0);
        if (!NT_SUCCESS(status))
        {
            if (status != STATUS_NOT_SUPPORTED &&   // only certain handle types can be duplicated
                status != STATUS_INVALID_HANDLE &&  // ?
                status != STATUS_ACCESS_DENIED)     // ?
            {
                fprintf(stderr, " [!] NtDuplicateObject(pid %u, handle %d): status 0x%08X\n", dwPid, handle.Handle, status);
            }
            CloseHandle(hOtherProc);
            continue;
        }
        while ((status = pNtQueryObject(hJob, ObjectTypeInformation,
            pObjType, ulObjTypeSize, NULL)) == 0x42)
        {
            ulObjTypeSize *= 2;
            pObjType = (PPUBLIC_OBJECT_TYPE_INFORMATION)safe_realloc(pObjType, ulObjTypeSize);
        }
        if (!NT_SUCCESS(status))
        {
            fprintf(stderr, " [!] NtQueryObject(pid %u, handle %d): status 0x%08X\n", dwPid, handle.Handle, status);
            CloseHandle(hJob);
            CloseHandle(hOtherProc);
            continue;
        }
        if (_wcsnicmp(L"job", pObjType->TypeName.Buffer, pObjType->TypeName.Length) != 0)
        {
            CloseHandle(hJob);
            CloseHandle(hOtherProc);
            continue;
        }
        if (!IsProcessInJob(hProcess, hJob, &bFound))
        {
            fprintf(stderr, " [!] IsProcessInJob(): code %u\n", GetLastError());
            CloseHandle(hJob);
            CloseHandle(hOtherProc);
            continue;
        }
        if (bFound)
        {
            *phJob = hJob;
            CloseHandle(hOtherProc);
            break;
        }
    }

    if (pHandles != NULL)
        safe_free(pHandles);
    if (pObjType != NULL)
        safe_free(pObjType);
    return bFound;
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
}

//if (getTokenInfo(hToken, TokenSandBoxInert, &pTokInfo, &dwTokInfoLen))

void printJobLimits(HANDLE hJob)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION extLimits = { 0 };
    JOBOBJECT_BASIC_UI_RESTRICTIONS uiLimits = { 0 };
    JOBOBJECT_NET_RATE_CONTROL_INFORMATION netLimits = { 0 };
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuLimits = { 0 };
    JOBOBJECT_SECURITY_LIMIT_INFORMATION secLimits = { 0 };
    BOOL bFound = FALSE;

    if (!QueryInformationJobObject(hJob, JobObjectExtendedLimitInformation, &extLimits, sizeof(extLimits), NULL))
    {
        fprintf(stderr, " [!] Unable to query QueryInformationJobObject"
            "(JobObjectExtendedLimitInformation), code %u\n", GetLastError());
    }
    else
    {
        if (flagsSet(extLimits.BasicLimitInformation.LimitFlags, JOB_OBJECT_LIMIT_BREAKAWAY_OK))
            printf(" [.] Allows breakout via CreateProcess(CREATE_BREAKAWAY_FROM_JOB)\n");
        else
            printf(" [+] Does not allow breakout via CreateProcess(CREATE_BREAKAWAY_FROM_JOB)\n");

        if (flagsSet(extLimits.BasicLimitInformation.LimitFlags, JOB_OBJECT_LIMIT_ACTIVE_PROCESS))
            printf(" [+] Maximum number of active processes: %lu\n", extLimits.BasicLimitInformation.ActiveProcessLimit);
        else
            printf(" [.] No limit on number of active processes\n");

        if (flagsSet(extLimits.BasicLimitInformation.LimitFlags, JOB_OBJECT_LIMIT_PROCESS_TIME))
            printf(" [+] Per process user time limit: %.6f s\n", ((double)extLimits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart) / 10000000);
        if (flagsSet(extLimits.BasicLimitInformation.LimitFlags, JOB_OBJECT_LIMIT_JOB_TIME))
            printf(" [+] Job user time limit: %.6f s\n", ((double)extLimits.BasicLimitInformation.PerJobUserTimeLimit.QuadPart) / 10000000);

        if (flagsSet(extLimits.BasicLimitInformation.LimitFlags, JOB_OBJECT_LIMIT_JOB_MEMORY))
            printf(" [+] Job memory commit limit: %s\n", prettifySize((double)extLimits.JobMemoryLimit));
        if (flagsSet(extLimits.BasicLimitInformation.LimitFlags, JOB_OBJECT_LIMIT_PROCESS_MEMORY))
            printf(" [+] Per-process memory commit limit: %s\n", prettifySize((double)extLimits.ProcessMemoryLimit));
        if (!flagsSet(extLimits.BasicLimitInformation.LimitFlags, JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_PROCESS_MEMORY))
            printf(" [.] No memory limit\n");
    }

    if (!QueryInformationJobObject(hJob, JobObjectCpuRateControlInformation, &cpuLimits, sizeof(cpuLimits), NULL))
    {
        printf(" [.] CPU timeslots not supported by OS\n");
    }
    else if (flagsSet(cpuLimits.ControlFlags, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED))
    {
        printf(" [+] Scheduling weight set to %lu\n", cpuLimits.Weight);
    }
    else if (flagsSet(cpuLimits.ControlFlags, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_MIN_MAX_RATE))
    {
        printf(" [+] CPU time share limited to %.2f %%\n", ((double)cpuLimits.MaxRate) / 100);
    }
    else if (flagsSet(cpuLimits.ControlFlags, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE))
    {
        printf(" [+] CPU time share limited to %.2f %%\n", ((double)cpuLimits.CpuRate) / 100);
    }
    else if (!flagsSet(extLimits.BasicLimitInformation.LimitFlags, JOB_OBJECT_LIMIT_PROCESS_TIME | JOB_OBJECT_LIMIT_JOB_TIME))
    {
        printf(" [.] No CPU time limit\n");
    }

    if (!QueryInformationJobObject(hJob, JobObjectBasicUIRestrictions, &uiLimits, sizeof(uiLimits), NULL))
    {
        printf(" [.] UI restriction not supported by OS\n");
    }
    else
    {
        if ((uiLimits.UIRestrictionsClass & JOB_OBJECT_UILIMIT_DESKTOP) != 0)
            printf(" [+] Cannot create nor switch desktop\n");
        else
            printf(" [.] Can create and switch desktops\n");

        if ((uiLimits.UIRestrictionsClass & JOB_OBJECT_UILIMIT_GLOBALATOMS) != 0)
            printf(" [+] Cannot use global atoms\n");
        else
            printf(" [.] Can access the global atom table\n");

        if ((uiLimits.UIRestrictionsClass & JOB_OBJECT_UILIMIT_HANDLES) != 0)
            printf(" [+] Cannot use USER handles from outside its job\n");
        else
            printf(" [.] Can use USER handles from outside its job\n");

        if ((uiLimits.UIRestrictionsClass & JOB_OBJECT_UILIMIT_READCLIPBOARD) != 0)
            printf(" [+] Cannot read clipboard\n");
        else
            printf(" [.] Can read clipboard\n");

        if ((uiLimits.UIRestrictionsClass & JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS) != 0)
            printf(" [+] Cannot alter system-wide parameters\n");
        else
            printf(" [.] Can alter system-wide parameters\n");
    }

    if (!QueryInformationJobObject(hJob, JobObjectNetRateControlInformation, &netLimits, sizeof(netLimits), NULL))
    {
        printf(" [.] Network bandwidth limiting not supported by OS\n");
    }
    else
    {
        if ((netLimits.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_ENABLE) != 0 &&
            (netLimits.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH) != 0)
        {
            printf(" [+] Network bandwidth limited to %s/s\n", prettifySize((double)netLimits.MaxBandwidth));
        }
        else
        {
            printf(" [.] No limit on network bandwidth\n");
        }
    }

    if (QueryInformationJobObject(hJob, JobObjectSecurityLimitInformation, &secLimits, sizeof(secLimits), NULL))
    {
        if (flagsSet(secLimits.SecurityLimitFlags, JOB_OBJECT_SECURITY_NO_ADMIN))
            printf(" [.] Local administrator SID disabled in job (obsolete)\n");
        if (flagsSet(secLimits.SecurityLimitFlags, JOB_OBJECT_SECURITY_FILTER_TOKENS))
        {
            printf(" [.] SIDs always disabled in job: (obsolete)\n");
            bFound = FALSE;
            for (DWORD i = 0; i < secLimits.SidsToDisable->GroupCount; i++)
            {
                printf("     ");
                printSID(secLimits.SidsToDisable->Groups[i].Sid, TRUE);
                printf("\n");
                bFound = TRUE;
            }
            if (!bFound)
                printf("     none\n");
            printf(" [.] Deny-only SID appended to tokens in job: (obsolete)\n");
            bFound = FALSE;
            for (DWORD i = 0; i < secLimits.RestrictedSids->GroupCount; i++)
            {
                printf("     ");
                printSID(secLimits.RestrictedSids->Groups[i].Sid, TRUE);
                printf("\n");
                bFound = TRUE;
            }
            if (!bFound)
                printf("     none\n");
        }
        if (flagsSet(secLimits.SecurityLimitFlags, JOB_OBJECT_SECURITY_RESTRICTED_TOKEN))
            printf(" [.] Only restricted tokens can be used in job (obsolete)\n");
        if (flagsSet(secLimits.SecurityLimitFlags, JOB_OBJECT_SECURITY_ONLY_TOKEN))
        {
            printf(" [.] Job is constrainted to run with the following token: (obsolete)\n");
            printToken(secLimits.JobToken);
        }
    }
}

void printMitigationPolicies(HANDLE hProcess)
{
    PROCESS_MITIGATION_DEP_POLICY depPolicy = { 0 };
    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = { 0 };
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynCodePolicy = { 0 };
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handleCheckPolicy = { 0 };
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscallDisablePolicy = { 0 };
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPointPolicy = { 0 };
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = { 0 };
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy = { 0 };
    PROCESS_MITIGATION_FONT_DISABLE_POLICY fontPolicy = { 0 };
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY loadPolicy = { 0 };

    if (!GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &depPolicy, sizeof(depPolicy)))
    {
        fprintf(stderr, " [!] Unable to query GetProcessMitigationPolicy(ProcessDEPPolicy), code %u\n", GetLastError());
    }
    else
    {
        if (depPolicy.Enable != 0)
        {
            printf(" [+] DEP enabled\n");
            if (depPolicy.Permanent != 0)
                printf(" [+] DEP cannot be disabled\n");
            else
                printf(" [.] DEP can be disabled\n");
            if (depPolicy.DisableAtlThunkEmulation)
                printf(" [+] DEP is fully supported (no ATL fixups)\n");
            else
                printf(" [.] DEP with ATL thunk emulation fixup\n");
        }
        else
        {
            printf(" [.] DEP disabled\n");
        }
    }
    if (!GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy)))
    {
        fprintf(stderr, " [!] Unable to query GetProcessMitigationPolicy(ProcessASLRPolicy), code %u\n", GetLastError());
    }
    else
    {
        if (aslrPolicy.EnableBottomUpRandomization)
            printf(" [+] Bottom-up ASLR randomisation\n");
        else
            printf(" [.] No bottom-up ASLR\n");
        if (aslrPolicy.EnableForceRelocateImages)
            printf(" [+] Images forcibly relocated\n");
        else
            printf(" [.] Images without /DYNAMICBASE are not forcibly relocated\n");
        if (aslrPolicy.EnableHighEntropy)
            printf(" [+] High entropy ASLR enabled\n");
        else
            printf(" [.] High entropy ASLR disabled\n");
        if (aslrPolicy.DisallowStrippedImages)
            printf(" [+] Stripped images without relocations are disallowed\n");
        else
            printf(" [.] Stripped images without relocation can still load\n");
    }
    if (!GetProcessMitigationPolicy(hProcess, ProcessDynamicCodePolicy, &dynCodePolicy, sizeof(dynCodePolicy)))
    {
        fprintf(stderr, " [!] Unable to query GetProcessMitigationPolicy(ProcessDynamicCodePolicy), code %u\n", GetLastError());
    }
    else
    {
        if (dynCodePolicy.ProhibitDynamicCode)
        {
            printf(" [+] Dynamic code prohibited\n");
            if (dynCodePolicy.AllowThreadOptOut)
                printf(" [.] Dynamic code can be re-allowed per-thread\n");
            else
                printf(" [+] Dynamic code cannot be re-allowed per-thread\n");
            if (dynCodePolicy.AllowRemoteDowngrade)
                printf(" [.] Dynamic code can be re-allowed by non-AppContainer processes\n");
            else
                printf(" [+] Dynamic code cannot be re-allowed by non-AppContainer processes\n");
        }
        else
        {
            printf(" [.] Dynamic code allowed\n");
        }
    }
    if (!GetProcessMitigationPolicy(hProcess, ProcessStrictHandleCheckPolicy, &handleCheckPolicy, sizeof(handleCheckPolicy)))
    {
        fprintf(stderr, " [!] Unable to query GetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy), code %u\n", GetLastError());
    }
    else
    {
        if (handleCheckPolicy.RaiseExceptionOnInvalidHandleReference && handleCheckPolicy.HandleExceptionsPermanentlyEnabled)
            printf(" [+] Invalid handle usage generates an exception\n");
        else if (handleCheckPolicy.RaiseExceptionOnInvalidHandleReference)
            printf(" [.] Invalid handle usage generates an exception, but can be disabled\n");
        else
            printf(" [.] Invalid handle usage is ignored\n");
    }
    if (!GetProcessMitigationPolicy(hProcess, ProcessSystemCallDisablePolicy, &syscallDisablePolicy, sizeof(syscallDisablePolicy)))
    {
        fprintf(stderr, " [!] Unable to query GetProcessMitigationPolicy(ProcessSystemCallDisablePolicy), code %u\n", GetLastError());
    }
    else
    {
        if (syscallDisablePolicy.DisallowWin32kSystemCalls && syscallDisablePolicy.AuditDisallowWin32kSystemCalls)
            printf(" [+] Win32k.sys syscalls are blocked, and audited\n");
        else if (syscallDisablePolicy.DisallowWin32kSystemCalls)
            printf(" [+] Win32k.sys syscalls are blocked\n");
        else
            printf(" [.] Win32k.sys syscalls are allowed\n");
    }
    if (!GetProcessMitigationPolicy(hProcess, ProcessExtensionPointDisablePolicy, &extensionPointPolicy, sizeof(extensionPointPolicy)))
    {
        fprintf(stderr, " [!] Unable to query GetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy), code %u\n", GetLastError());
    }
    else
    {
        if (extensionPointPolicy.DisableExtensionPoints)
            printf(" [+] Legacy DLL extension points are disabled\n");
        else
            printf(" [.] Legacy DLL extension points are still enabled (AppInit DLLs, SetWindowsHookEx, etc.)\n");
    }
    if (!GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy)))
    {
        fprintf(stderr, " [!] Unable to query GetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy), code %u\n", GetLastError());
    }
    else
    {
        if (cfgPolicy.EnableControlFlowGuard)
        {
            printf(" [+] Control Flow Guard enabled\n");
            if (cfgPolicy.EnableExportSuppression)
                printf(" [+] Exported functions are disallowed indirect calls by default\n");
            else
                printf(" [.] Exported functions are allowed as indirect calls by default\n");
            if (cfgPolicy.StrictMode)
                printf(" [+] Only CFG-enabled DLLs can be loaded\n");
            else
                printf(" [.] Non-CFG-enabled DLLs can be loaded\n");
        }
        else
        {
            printf(" [.] Control Flow Guard disabled\n");
        }
    }
    if (!GetProcessMitigationPolicy(hProcess, ProcessSignaturePolicy, &signaturePolicy, sizeof(signaturePolicy)))
    {
        fprintf(stderr, " [!] Unable to query GetProcessMitigationPolicy(ProcessSignaturePolicy), code %u\n", GetLastError());
    }
    else
    {
        if (signaturePolicy.MicrosoftSignedOnly)
            printf(" [+] Only Microsoft signed DLLs can be loaded\n");
        if (signaturePolicy.StoreSignedOnly)
            printf(" [+] Only Microsoft Store signed DLLs can be loaded\n");
        if (signaturePolicy.MitigationOptIn)
            printf(" [+] Only Microsoft/Microsoft Store/WHQL signed DLLs can be loaded\n");
        if (!signaturePolicy.MicrosoftSignedOnly && !signaturePolicy.StoreSignedOnly && !signaturePolicy.MitigationOptIn)
            printf(" [.] Arbitrary DLLs can be loaded/injected\n");
    }
    if (!GetProcessMitigationPolicy(hProcess, ProcessFontDisablePolicy, &fontPolicy, sizeof(fontPolicy)))
    {
        fprintf(stderr, " [!] Unable to query GetProcessMitigationPolicy(ProcessFontDisablePolicy), code %u\n", GetLastError());
    }
    else
    {
        if (fontPolicy.DisableNonSystemFonts)
            printf(" [+] Only system fonts can be loaded\n");
        else
            printf(" [.] Arbitrary fonts can be loaded\n");
    }
    if (!GetProcessMitigationPolicy(hProcess, ProcessImageLoadPolicy, &loadPolicy, sizeof(loadPolicy)))
    {
        fprintf(stderr, " [!] Unable to query GetProcessMitigationPolicy(ProcessImageLoadPolicy), code %u\n", GetLastError());
    }
    else
    {
        if (loadPolicy.NoRemoteImages)
            printf(" [+] Cannot load executables from remote shares\n");
        else
            printf(" [.] Can load executables from remote shares\n");
        if (loadPolicy.AuditNoRemoteImages)
            printf(" [+] Cannot load executables with Low integrity label\n");
        else
            printf(" [.] Can load executables with arbitrary integrity labels\n");
        if (loadPolicy.PreferSystem32Images)
            printf(" [+] executables loaded are searched in System32 directory first\n");
        else
            printf(" [.] Classic executable search path in use");
    }
}

VOID print_usage_exit()
{
    fprintf(stderr, "tristitude v1.0 - Process security policy enumerator\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: tristitude.exe [/p <PID>]\n");
    exit(1);
}

int main(int argc, const char *argv[])
{
    HANDLE hMyToken = NULL;
    TOKEN_PRIVILEGES priv = { 0 };
    DWORD dwTargetPid = 0;
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hToken = NULL;
    BOOL bInJob = FALSE;

    pNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL)
        fprintf(stderr, " [!] GetProcAddress(NtQuerySystemInformation): code %u\n", GetLastError());
    pNtDuplicateObject = (_NtDuplicateObject)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtDuplicateObject");
    if (pNtDuplicateObject == NULL)
        fprintf(stderr, " [!] GetProcAddress(NtDuplicateObject): code %u\n", GetLastError());
    pNtQueryObject = (_NtQueryObject)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryObject");
    if (pNtQueryObject == NULL)
        fprintf(stderr, " [!] GetProcAddress(NtQueryObject): code %u\n", GetLastError());

    if (argc == 2)
    {
        dwTargetPid = atoi(argv[1]);
        if (dwTargetPid == 0)
        {
            fprintf(stderr, "Error: invalid PID\n");
            print_usage_exit();
        }
    }
    else if (argc < 1 || argc > 2)
    {
        print_usage_exit();
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hMyToken))
    {
        fprintf(stderr, " [!] OpenProcessToken(GetCurrentProcess()): code %u\n", GetLastError());
        exit(GetLastError());
    }

    priv.PrivilegeCount = 1;
    priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
    {
        fprintf(stderr, " [!] LookupPrivilegeValue(): code %u\n", GetLastError());
        exit(GetLastError());
    }
    if (!AdjustTokenPrivileges(hMyToken, FALSE, &priv, 0, NULL, NULL))
    {
        fprintf(stderr, " [!] AdjustTokenPrivileges(): code %u\n", GetLastError());
        exit(GetLastError());
    }
    CloseHandle(hMyToken);

    if (dwTargetPid > 0)
    {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, dwTargetPid);
        if (hProcess == NULL)
        {
            fprintf(stderr, " [!] Unable to open process %u, code %u\n", dwTargetPid, GetLastError());
            exit(GetLastError());
        }
    }

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        fprintf(stderr, " [!] Unable to query OpenProcessToken(), code %u\n", GetLastError());
    }
    else
    {
        printf(" [.] Process is running with token:\n");
        printToken(hToken);
    }

    if (!IsProcessInJob(hProcess, NULL, &bInJob))
    {
        fprintf(stderr, " [!] Unable to query IsProcessInJob(), code %u\n", GetLastError());
    }
    else if (bInJob)
    {
        HANDLE hJob = NULL;
        printf(" [+] Currently running in a job\n");

        if (GetProcessId(hProcess) == GetCurrentProcessId())
            printJobLimits(NULL);
        else if (getProcessJob(hProcess, &hJob))
            printJobLimits(hJob);
        else
            printf(" [!] Unable to find associated job object, partial results only\n");
    }
    else
    {
        printf(" [.] Not running in a job\n");
    }

    printMitigationPolicies(hProcess);

    CloseHandle(hToken);
    return 0;
}

