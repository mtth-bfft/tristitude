#include <stdio.h>
#include "mitigation.h"

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