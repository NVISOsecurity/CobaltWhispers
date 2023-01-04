#pragma once

#include <windows.h>

#if _WIN64

#define ZwSetValueKey NtSetValueKey

__asm__("NtSetValueKey: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x03D1D2A80 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwOpenKeyEx NtOpenKeyEx

__asm__("NtOpenKeyEx: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x06DEA516E \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwDeleteKey NtDeleteKey

__asm__("NtDeleteKey: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0EB39D880 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwClose NtClose

__asm__("NtClose: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0029AF097 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#endif