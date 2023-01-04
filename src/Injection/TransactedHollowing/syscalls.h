#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef SW2_HEADER_H_
#define SW2_HEADER_H_

#include <windows.h>
#include "syscalls-asm.h"
#include "beacon.h"

#ifdef _WIN64
#define ULONGSIZE ULONG64
#else
#define ULONGSIZE ULONG32
#endif

#ifdef _WIN64
#define PEB_OFFSET 0x60
#define READ_MEMLOC __readgsqword
#else
#define PEB_OFFSET 0x30
#define READ_MEMLOC __readfsdword
#endif

#define SW2_SEED 0x4565F109

#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

typedef struct _SW2_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
} SW2_SYSCALL_ENTRY, *PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
    DWORD Count;
    SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, *PSW2_SYSCALL_LIST;

typedef struct _SW2_PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} SW2_PEB_LDR_DATA, *PSW2_PEB_LDR_DATA;

typedef struct _SW2_LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
} SW2_LDR_DATA_TABLE_ENTRY, *PSW2_LDR_DATA_TABLE_ENTRY;

typedef struct _SW2_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PSW2_PEB_LDR_DATA Ldr;
} SW2_PEB, *PSW2_PEB;

DWORD SW2_HashSyscall(PCSTR FunctionName);
BOOL SW2_PopulateSyscallList();
EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash) asm ("SW2_GetSyscallNumber");
EXTERN_C BOOL IsWoW64() asm ("IsWoW64");
EXTERN_C PVOID GetSyscallAddress(void) asm ("GetSyscallAddress");

#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x20007
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON 0x0000100000000000
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_IMAGE_NOT_AT_BASE 0x40000003
#define OBJ_CASE_INSENSITIVE 0x00000040

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef struct PROC_THREAD_ATTRIBUTE_ENTRY
{
    DWORD_PTR   Attribute;
    SIZE_T      cbSize;
    PVOID       lpValue;
} PROC_THREAD_ATTRIBUTE_ENTRY, *LPPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST
{
    DWORD                          dwFlags;
    ULONG                          Size;
    ULONG                          Count;
    ULONG                          Reserved;
    PULONG                         Unknown;
    PROC_THREAD_ATTRIBUTE_ENTRY    Entries[ANYSIZE_ARRAY];
} PROC_THREAD_ATTRIBUTE_LIST, *LPPROC_THREAD_ATTRIBUTE_LIST;

typedef struct STARTUPINFOEXA {
    STARTUPINFOA StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXA,*LPSTARTUPINFOEXA;

EXTERN_C NTSTATUS NtCreateTransaction(
        OUT PHANDLE TransactionHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN LPGUID Uow OPTIONAL,
        IN HANDLE TmHandle OPTIONAL,
        IN ULONG CreateOptions OPTIONAL,
        IN ULONG IsolationLevel OPTIONAL,
        IN ULONG IsolationFlags OPTIONAL,
        IN PLARGE_INTEGER Timeout OPTIONAL,
        IN PUNICODE_STRING Description OPTIONAL) asm("NtCreateTransaction");

/*
EXTERN_C NTSTATUS NtCreateFile(
        OUT PHANDLE FileHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        OUT PIO_STATUS_BLOCK IoStatusBlock,
        IN PLARGE_INTEGER AllocationSize OPTIONAL,
        IN ULONG FileAttributes,
        IN ULONG ShareAccess,
        IN ULONG CreateDisposition,
        IN ULONG CreateOptions,
        IN PVOID EaBuffer OPTIONAL,
        IN ULONG EaLength) asm("NtCreateFile");
*/

EXTERN_C NTSTATUS NtWriteFile(
        IN HANDLE FileHandle,
        IN HANDLE Event OPTIONAL,
        IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
        IN PVOID ApcContext OPTIONAL,
        OUT PIO_STATUS_BLOCK IoStatusBlock,
        IN PVOID Buffer,
        IN ULONG Length,
        IN PLARGE_INTEGER ByteOffset OPTIONAL,
        IN PULONG Key OPTIONAL) asm("NtWriteFile");

EXTERN_C NTSTATUS NtCreateSection(
        OUT PHANDLE SectionHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN PLARGE_INTEGER MaximumSize OPTIONAL,
        IN ULONG SectionPageProtection,
        IN ULONG AllocationAttributes,
        IN HANDLE FileHandle OPTIONAL) asm("NtCreateSection");

EXTERN_C NTSTATUS NtMapViewOfSection(
        IN HANDLE SectionHandle,
        IN HANDLE ProcessHandle,
        IN OUT PVOID BaseAddress,
        IN ULONG ZeroBits,
        IN SIZE_T CommitSize,
        IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
        IN OUT PSIZE_T ViewSize,
        IN SECTION_INHERIT InheritDisposition,
        IN ULONG AllocationType,
        IN ULONG Win32Protect) asm("NtMapViewOfSection");

EXTERN_C NTSTATUS NtGetContextThread(
        IN HANDLE ThreadHandle,
        IN OUT PCONTEXT ThreadContext) asm("NtGetContextThread");

EXTERN_C NTSTATUS NtSetContextThread(
        IN HANDLE ThreadHandle,
        IN PCONTEXT Context) asm("NtSetContextThread");

EXTERN_C NTSTATUS NtWriteVirtualMemory(
        IN HANDLE ProcessHandle,
        IN PVOID BaseAddress,
        IN PVOID Buffer,
        IN SIZE_T NumberOfBytesToWrite,
        OUT PSIZE_T NumberOfBytesWritten OPTIONAL) asm("NtWriteVirtualMemory");

EXTERN_C NTSTATUS NtResumeThread(
        IN HANDLE ThreadHandle,
        IN OUT PULONG PreviousSuspendCount OPTIONAL) asm("NtResumeThread");

EXTERN_C NTSTATUS NtOpenProcess(
        OUT PHANDLE ProcessHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        IN PCLIENT_ID ClientId OPTIONAL) asm("NtOpenProcess");

#endif