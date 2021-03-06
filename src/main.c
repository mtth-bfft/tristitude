#include <stdio.h>
#include <Windows.h>
#include "job.h"
#include "mitigation.h"
#include "token.h"
#include "utils.h"

_NtQuerySystemInformation pNtQuerySystemInformation = NULL;
_NtDuplicateObject pNtDuplicateObject = NULL;
_NtQueryObject pNtQueryObject = NULL;

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
    HANDLE hJob = NULL;

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

    // Enable SE_DEBUG_PRIVILEGE
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

    // Get a handle on the target process, if we're not the target process
    if (dwTargetPid > 0)
    {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, dwTargetPid);
        if (hProcess == NULL)
        {
            fprintf(stderr, " [!] Unable to open process %u, code %u\n", dwTargetPid, GetLastError());
            exit(GetLastError());
        }
    }

    // Print security token properties
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        fprintf(stderr, " [!] Unable to query OpenProcessToken(), code %u\n", GetLastError());
    }
    else
    {
        printf(" [.] Process is running with token:\n");
        printToken(hToken);
    }

    // Check Job security properties
    if (!IsProcessInJob(hProcess, NULL, &bInJob))
    {
        fprintf(stderr, " [!] Unable to query IsProcessInJob(), code %u\n", GetLastError());
    }
    else if (bInJob)
    {
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

    // Check mitigation policies, if any
    printMitigationPolicies(hProcess);

    if (hJob != NULL)
        CloseHandle(hJob);
    if (hToken != NULL)
        CloseHandle(hToken);
    return 0;
}