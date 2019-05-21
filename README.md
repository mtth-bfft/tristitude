# tristitude

A simple process security policy enumerator. This project has been superseded by https://github.com/mtth-bfft/ntsec, which now has the same functionalities and many more :)

Currently tested settings mainly include (per-process, per-executable or system-wide) job properties and mitigation policies. This tool is an archived project based on Google's great [sandbox-attacksurface-analysis-tools](https://github.com/google/sandbox-attacksurface-analysis-tools).

## Usage

To display information about an already running process, use `.\tristitude.exe /p <pid>`. Otherwise, if you can run arbitrary commands inside a sandbox you want to test, run the binary without arguments from within.

## Example

Here are the results you can get when running in a Docker container with memory and cpu restrictions:

```
 [.] Process is running with token:
     Primary token
     Session ID: 0x3
     User:   S-1-5-93-2-1 (User Manager\ContainerAdministrator)
     Enabled SIDs:
             S-1-1-0 (\Everyone) (mandatory)
             S-1-5-32-545 (BUILTIN\Users) (mandatory)
             S-1-5-6 (NT AUTHORITY\SERVICE) (mandatory)
             S-1-5-11 (NT AUTHORITY\Authenticated Users) (mandatory)
             S-1-5-15 (NT AUTHORITY\This Organization) (mandatory)
             S-1-5-5-0-1872867 (NT AUTHORITY\LogonSessionId_0_1872867) (mandatory)
             S-1-2-0 (\LOCAL) (mandatory)
             S-1-5-32-544 (BUILTIN\Administrators) (mandatory)
             S-1-5-93-0 (unable to resolve, error 1332) (mandatory)
     Deny-only SIDs:
             none
     Restricted SIDs:
             none
     Privileges:
             SeIncreaseQuotaPrivilege
             SeSecurityPrivilege
             SeTakeOwnershipPrivilege
             SeLoadDriverPrivilege
             SeSystemProfilePrivilege
             SeSystemtimePrivilege
             SeProfileSingleProcessPrivilege
             SeIncreaseBasePriorityPrivilege
             SeCreatePagefilePrivilege
             SeBackupPrivilege
             SeRestorePrivilege
             SeShutdownPrivilege
             SeDebugPrivilege
             SeSystemEnvironmentPrivilege
             SeChangeNotifyPrivilege
             SeRemoteShutdownPrivilege
             SeUndockPrivilege
             SeManageVolumePrivilege
             SeImpersonatePrivilege
             SeCreateGlobalPrivilege
             SeIncreaseWorkingSetPrivilege
             SeTimeZonePrivilege
             SeCreateSymbolicLinkPrivilege
             SeDelegateSessionUserImpersonatePrivilege
     Mandatory policy:
             NO_WRITE_UP
             NEW_PROCESS_MIN
     Protected process trust: none
 [+] Currently running in a job
 [+] Does not allow breakout via CreateProcess(CREATE_BREAKAWAY_FROM_JOB)
 [.] No limit on number of active processes
 [+] Job memory commit limit: 200.00 MiB
 [.] No memory limit
 [+] CPU time share limited to 75.00 %
 [.] Can create and switch desktops
 [.] Can access the global atom table
 [.] Can use USER handles from outside its job
 [.] Can read clipboard
 [.] Can alter system-wide parameters
 [.] No limit on network bandwidth
 [!] Unable to query GetProcessMitigationPolicy(ProcessDEPPolicy), code 87
 [+] Bottom-up ASLR randomisation
 [.] Images without /DYNAMICBASE are not forcibly relocated
 [+] High entropy ASLR enabled
 [.] Stripped images without relocation can still load
 [.] Dynamic code allowed
 [.] Invalid handle usage is ignored
 [.] Win32k.sys syscalls are allowed
 [.] Legacy DLL extension points are still enabled (AppInit DLLs, SetWindowsHookEx, etc.)
 [.] Control Flow Guard disabled
 [.] Arbitrary DLLs can be loaded/injected
 [.] Arbitrary fonts can be loaded
 [.] Can load executables from remote shares
 [.] Can load executables with arbitrary integrity labels
 [.] Classic executable search path in use
```
