#include <stdio.h>
#include "job.h"
#include "token.h"
#include "utils.h"

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
        status = pNtDuplicateObject(hOtherProc, (HANDLE)handle.Handle, GetCurrentProcess(), &hJob, JOB_OBJECT_QUERY, 0, 0);
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