#pragma once

#include <Windows.h>
#include "syscalls.h"

typedef CONST WCHAR *LPCWCHAR, *PCWCHAR;

//defs
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define STATUS_BUFFER_OVERFLOW 0x80000005

//imports
//clib
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$wcscat_s(wchar_t*, rsize_t, const wchar_t*);
DECLSPEC_IMPORT void* __cdecl  MSVCRT$memcpy(LPVOID, LPVOID, size_t);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$wcscmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_wtoi(const wchar_t*);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$strcpy_s(char*, rsize_t, const char*);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$wcstombs_s(size_t*, char*, size_t, const wchar_t*, size_t);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcstok(wchar_t*, const wchar_t*, wchar_t**);
//kernel32
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
//ntdll

//macro
#define malloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define memcpy MSVCRT$memcpy
#define wcscat_s MSVCRT$wcscat_s
#define strcpy MSVCRT$strcpy
#define wcscmp MSVCRT$wcscmp
#define _wtoi MSVCRT$_wtoi
#define strcpy_s MSVCRT$strcpy_s
#define wcstombs_s MSVCRT$wcstombs_s
#define wcstok MSVCRT$wcstok

#define GetProcessHeap KERNEL32$GetProcessHeap
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapFree KERNEL32$HeapFree

//prototypes
NTSTATUS SendIOCTL(HANDLE hDevice, DWORD ioctl, PVOID InputBuffer, SIZE_T szInputBuffer, BOOL Output);
NTSTATUS GetHandle(PHANDLE DeviceHandle);
NTSTATUS DisplayOutput(HANDLE hDevice, DWORD ioctl, PVOID bufferIn, DWORD szBufferIn);
void ParseArgs(wchar_t* source, wchar_t**, PSIZE_T outSize);