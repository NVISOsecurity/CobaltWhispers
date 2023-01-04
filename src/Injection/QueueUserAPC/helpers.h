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