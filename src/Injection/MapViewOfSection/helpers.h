DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);

char* xordecrypt(char* in, int len)
{    
    char* out = (char*)MSVCRT$malloc(sizeof(char)*len);

    for(int i = 0; i < len; i++)
    {
        out[i] = in[i] ^ ((len - 1) % 255);
    }
    return out;
}

void myMemcpy(PVOID Destination, const PVOID Source, SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;
}

void myZeroMemory(PVOID Destination, SIZE_T Size)
{
    PULONG Dest = (PULONG)Destination;
    SIZE_T Count = Size / sizeof(ULONG);

    while (Count > 0)
    {
        *Dest = 0;
        Dest++;
        Count--;
    }
    return;
}