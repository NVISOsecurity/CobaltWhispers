#pragma once

#include <Windows.h>
#include "syscalls.h"

// defs
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001

//imports
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);

//macro
#define malloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
//kernel32
#define GetProcessHeap KERNEL32$GetProcessHeap
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapFree KERNEL32$HeapFree
#define LookupPrivilegeValueW ADVAPI32$LookupPrivilegeValueW

//prototypes
BOOLEAN ChangeTokenPrivileges(BOOL Enable);
NTSTATUS UnloadDriver(LPCWSTR RegKey, LPCWSTR DriverPath, BOOLEAN Remove);
BOOL Cleanup(LPCWSTR key, LPCWSTR path);
NTSTATUS DeleteRegKey(LPCWSTR key);
NTSTATUS DeleteBinary(LPCWSTR path);