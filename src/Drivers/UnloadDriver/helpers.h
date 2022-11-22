#pragma once
#include <Windows.h>
#include "UnloadDriver.h"

//prototypes
void RtlInitUnicodeString(PUNICODE_STRING destination, PCWSTR source);
size_t cwcscpy(wchar_t* dest, const wchar_t* src);
size_t cwmemcpy(wchar_t* s1, const wchar_t* s2, size_t n);
size_t cmemcpy(char* dst, const char* src, size_t size);
size_t cwcslen(const wchar_t* src);
void cZeroMemory(PVOID, SIZE_T);
int rotl(int x, int n);
wchar_t* wobfsct(wchar_t* in, int len);
char* aobfsct(char* in, int len);

char* aobfsct(char* in, int len)
{
    char* out = (char*)malloc(sizeof(char) * (len + 1)); //+1 account for \0

    for (int i = 0; i < len; i++)
    {
        out[i] = in[i] ^ (rotl(len, i) % 255);
    }
    out[len] = '\0';
    return out;
}

wchar_t* wobfsct(wchar_t* in, int len)
{
    wchar_t* out = (wchar_t*)malloc(sizeof(wchar_t) * (len + 1)); //+1 account for \0

    for (int i = 0; i < len; i++)
    {
        out[i] = in[i] ^ (rotl(len, i) % 255);
    }
    out[len] = L'\0';
    return out;
}

int rotl(int x, int n) {
    return (x << n) | (x >> (0x1F & (32 + ~n + 1))) & ~(0xFFFFFFFF << n);
}

void RtlInitUnicodeString(PUNICODE_STRING destination, PCWSTR source) {
    destination->Buffer = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cwcslen(source) + 1) * sizeof(WCHAR));
    USHORT length = (USHORT)cwcscpy(destination->Buffer, source);
    destination->MaximumLength = length + 2;
    destination->Length = length;
}

size_t cwcscpy(wchar_t* dest, const wchar_t* src) {
    return cwmemcpy(dest, src, cwcslen(src));
}

size_t cwmemcpy(wchar_t* s1, const wchar_t* s2, size_t n) {
    return cmemcpy((char*)s1, (char*)s2, n * sizeof(wchar_t));
}

size_t cmemcpy(char* dst, const char* src, size_t size) {
    int x;
    for (x = 0; x < size; x++) {
        *dst = *src;
        dst++;
        src++;
    }
    return size;
}

size_t cwcslen(const wchar_t* src) {
    size_t len = 0;

    while (src[len] != L'\0') {
        if (src[++len] == L'\0') {
            return len;
        }
        if (src[++len] == L'\0') {
            return len;
        }
        if (src[++len] == L'\0') {
            return len;
        }
        ++len;
    }
    return len;
}

void cZeroMemory(PVOID destination, SIZE_T size)
{
    PULONG dest = (PULONG)destination;
    SIZE_T count = size / sizeof(ULONG);

    while(count > 0) {
        *dest = 0;
        dest++;
        count--;
    }
    return;
}
