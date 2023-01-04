#pragma once

#include <Windows.h>
#include "syscalls.h"

// defs
#ifndef IN_REGION
#define IN_REGION(x, Base, Size) (((ULONG_PTR)(x) >= (ULONG_PTR)(Base)) && ((ULONG_PTR)(x) <= (ULONG_PTR)(Base) + (ULONG_PTR)(Size)))
#endif
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OPEN_IF 0x00000003
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_IMAGE_ALREADY_LOADED 0xC000010EL
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035L
#define STATUS_OBJECT_NAME_EXISTS 0x4000000L
#define PAGE_SIZE 0x1000ull
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#define STATUS_BUFFER_OVERFLOW 0x80000005L
#define STATUS_PROCEDURE_NOT_FOUND 0xC000007AL
#define VM_LOCK_1 0x0001
#define FILE_OPEN 0x00000001
#define STATUS_INSUFFICIENT_RESOURCES 0xC000009AL

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _LDR_DATA_TABLE_ENTRY_COMPATIBLE {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    } DUMMYUNION0;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1; // Size=4 Offset=104 BitOffset=0 BitCount=1
            ULONG MarkedForRemoval : 1; // Size=4 Offset=104 BitOffset=1 BitCount=1
            ULONG ImageDll : 1; // Size=4 Offset=104 BitOffset=2 BitCount=1
            ULONG LoadNotificationsSent : 1; // Size=4 Offset=104 BitOffset=3 BitCount=1
            ULONG TelemetryEntryProcessed : 1; // Size=4 Offset=104 BitOffset=4 BitCount=1
            ULONG ProcessStaticImport : 1; // Size=4 Offset=104 BitOffset=5 BitCount=1
            ULONG InLegacyLists : 1; // Size=4 Offset=104 BitOffset=6 BitCount=1
            ULONG InIndexes : 1; // Size=4 Offset=104 BitOffset=7 BitCount=1
            ULONG ShimDll : 1; // Size=4 Offset=104 BitOffset=8 BitCount=1
            ULONG InExceptionTable : 1; // Size=4 Offset=104 BitOffset=9 BitCount=1
            ULONG ReservedFlags1 : 2; // Size=4 Offset=104 BitOffset=10 BitCount=2
            ULONG LoadInProgress : 1; // Size=4 Offset=104 BitOffset=12 BitCount=1
            ULONG LoadConfigProcessed : 1; // Size=4 Offset=104 BitOffset=13 BitCount=1
            ULONG EntryProcessed : 1; // Size=4 Offset=104 BitOffset=14 BitCount=1
            ULONG ProtectDelayLoad : 1; // Size=4 Offset=104 BitOffset=15 BitCount=1
            ULONG ReservedFlags3 : 2; // Size=4 Offset=104 BitOffset=16 BitCount=2
            ULONG DontCallForThreads : 1; // Size=4 Offset=104 BitOffset=18 BitCount=1
            ULONG ProcessAttachCalled : 1; // Size=4 Offset=104 BitOffset=19 BitCount=1
            ULONG ProcessAttachFailed : 1; // Size=4 Offset=104 BitOffset=20 BitCount=1
            ULONG CorDeferredValidate : 1; // Size=4 Offset=104 BitOffset=21 BitCount=1
            ULONG CorImage : 1; // Size=4 Offset=104 BitOffset=22 BitCount=1
            ULONG DontRelocate : 1; // Size=4 Offset=104 BitOffset=23 BitCount=1
            ULONG CorILOnly : 1; // Size=4 Offset=104 BitOffset=24 BitCount=1
            ULONG ChpeImage : 1; // Size=4 Offset=104 BitOffset=25 BitCount=1
            ULONG ReservedFlags5 : 2; // Size=4 Offset=104 BitOffset=26 BitCount=2
            ULONG Redirected : 1; // Size=4 Offset=104 BitOffset=28 BitCount=1
            ULONG ReservedFlags6 : 2; // Size=4 Offset=104 BitOffset=29 BitCount=2
            ULONG CompatDatabaseProcessed : 1; // Size=4 Offset=104 BitOffset=31 BitCount=1
        };
    } ENTRYFLAGSUNION;
    WORD ObsoleteLoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    } DUMMYUNION1;
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    } DUMMYUNION2;
    //fields below removed for compatibility, if you need them use LDR_DATA_TABLE_ENTRY_FULL
} LDR_DATA_TABLE_ENTRY_COMPATIBLE, * PLDR_DATA_TABLE_ENTRY_COMPATIBLE;
typedef LDR_DATA_TABLE_ENTRY_COMPATIBLE LDR_DATA_TABLE_ENTRY;
typedef LDR_DATA_TABLE_ENTRY_COMPATIBLE* PLDR_DATA_TABLE_ENTRY;
typedef LDR_DATA_TABLE_ENTRY* PCLDR_DATA_TABLE_ENTRY;

/*
typedef struct _OSVERSIONINFOW {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR  szCSDVersion[128];     // Maintenance string for PSS usage
} OSVERSIONINFOW, * POSVERSIONINFOW, * LPOSVERSIONINFOW, RTL_OSVERSIONINFOW, * PRTL_OSVERSIONINFOW;
*/

//imports
//clib
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$wcscat_s(wchar_t*, rsize_t, const wchar_t*);
DECLSPEC_IMPORT void __cdecl   MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void* __cdecl  MSVCRT$memcpy(LPVOID, LPVOID, size_t);
//kernel32
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
DECLSPEC_IMPORT UINT WINAPI KERNEL32$GetSystemDirectoryW(LPWSTR, UINT);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
//ntdll
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$LdrFindEntryForAddress(PVOID, PLDR_DATA_TABLE_ENTRY*);
DECLSPEC_IMPORT ULONG NTAPI NTDLL$RtlLengthRequiredSid(ULONG SubAuthorityCount);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlCreateAcl(PACL Acl, ULONG AclLength, ULONG AclRevision);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlInitializeSid(PSID Sid, PSID_IDENTIFIER_AUTHORITY IdentifierAuthority, UCHAR SubAuthorityCount);
DECLSPEC_IMPORT PULONG NTAPI NTDLL$RtlSubAuthoritySid(PSID Sid, ULONG SubAuthority);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlAddAccessAllowedAce(PACL Acl, ULONG AceRevision, ACCESS_MASK AccessMask, PSID Sid);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlCreateSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Revision);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlSetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN DaclPresent, PACL Dacl, BOOLEAN DaclDefaulted);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

//clib
#define strcmp MSVCRT$strcmp
#define wcscat_s MSVCRT$wcscat_s
#define memset MSVCRT$memset
#define memcpy MSVCRT$memcpy
//macro
#define malloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
//kernel32
#define GetProcessHeap KERNEL32$GetProcessHeap
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapFree KERNEL32$HeapFree
#define LookupPrivilegeValueW ADVAPI32$LookupPrivilegeValueW
#define GetSystemDirectoryW KERNEL32$GetSystemDirectoryW
#define LoadLibraryExW KERNEL32$LoadLibraryExW
//ntdll
#define LdrFindEntryForAddress NTDLL$LdrFindEntryForAddress
#define RtlLengthRequiredSid NTDLL$RtlLengthRequiredSid
#define RtlCreateAcl NTDLL$RtlCreateAcl
#define RtlInitializeSid NTDLL$RtlInitializeSid
#define RtlSubAuthoritySid NTDLL$RtlSubAuthoritySid
#define RtlAddAccessAllowedAce NTDLL$RtlAddAccessAllowedAce
#define RtlCreateSecurityDescriptor NTDLL$RtlCreateSecurityDescriptor
#define RtlSetDaclSecurityDescriptor NTDLL$RtlSetDaclSecurityDescriptor
#define RtlGetVersion NTDLL$RtlGetVersion

//prototypes
//driver
BOOLEAN ChangeTokenPrivileges(BOOL Enable);
SIZE_T WriteBufferToFile(LPWSTR lpFileName, PVOID Buffer, SIZE_T BufferSize);
NTSTATUS CreateDriverEntry(LPCWSTR DriverPath, LPCWSTR KeyName);
NTSTATUS LoadDriver(PHANDLE DeviceHandle, LPCWSTR DeviceName, BOOL Callback, BOOL Start, LPCWSTR RegKey, LPCWSTR DriverPath, BOOLEAN UnloadPreviousInstance);
NTSTATUS StartDriver(PHANDLE DeviceHandle, LPCWSTR lpDeviceName, BOOL Callback);
NTSTATUS UnloadDriver(PHANDLE DeviceHandle, LPCWSTR RegKey, LPCWSTR DriverPath, BOOLEAN Remove);
//DSE
NTSTATUS ControlDSE(HANDLE DeviceHandle, ULONG buildNumber, ULONG DSEValue);
ULONG_PTR QueryVariable(ULONG buildNumber);
NTSTATUS QueryCiEnabled(HMODULE ImageMappedBase, ULONG_PTR ImageLoadedBase, ULONG_PTR* ResolvedAddress, SIZE_T SizeOfImage);
NTSTATUS QueryCiOptions(HMODULE ImageMappedBase, ULONG_PTR ImageLoadedBase, ULONG_PTR* ResolvedAddress, ULONG buildNumber);
//misc
ULONG GetBuildNumber();
BOOL Cleanup(LPCWSTR key, LPCWSTR path);
NTSTATUS DeleteRegKey(LPCWSTR key);
NTSTATUS DeleteBinary(LPCWSTR path);
PVOID GetLoadedModulesList(PULONG ReturnLength);
ULONG_PTR GetModuleBaseByName(const char* ModuleName, PULONG ImageSize);
NTSTATUS QueryImageSize(PVOID ImageBase, PSIZE_T ImageSize);
ULONG CheckInstructionBlock(PBYTE Code, ULONG Offset);
NTSTATUS CreateSystemAdminAccessSD(PSECURITY_DESCRIPTOR* SecurityDescriptor, PACL* DefaultAcl);
//Nal driver
NTSTATUS NalPostOpenCallback(PHANDLE DeviceHandle);