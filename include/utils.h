#pragma once
#include <Windows.h>

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

extern _NtQuerySystemInformation pNtQuerySystemInformation;
extern _NtDuplicateObject pNtDuplicateObject;
extern _NtQueryObject pNtQueryObject;

PVOID safe_alloc(DWORD dwBytes);
PVOID safe_realloc(PVOID pOld, DWORD dwBytes);
VOID safe_free(PVOID pBuf);
PCSTR prettifySize(double bytes);