#pragma once
#include <windows.h>

#if _WIN64

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

#define ZwOpenProcess NtOpenProcess

__asm__("NtOpenProcess: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0D4401B1A \n\
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

#define ZwWriteVirtualMemory NtWriteVirtualMemory

__asm__("NtWriteVirtualMemory: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0C5502BC7 \n\
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

#define ZwAllocateVirtualMemory NtAllocateVirtualMemory

__asm__("NtAllocateVirtualMemory: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x040560A9B \n\
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

#define ZwOpenThread NtOpenThread

__asm__("NtOpenThread: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0A30EA796 \n\
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

#define ZwSuspendThread NtSuspendThread

__asm__("NtSuspendThread: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0B20DECB7 \n\
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

#define ZwQueueApcThread NtQueueApcThread

__asm__("NtQueueApcThread: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x01450C966 \n\
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

#define ZwResumeThread NtResumeThread

__asm__("NtResumeThread: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x034AC281D \n\
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

#define ZwProtectVirtualMemory NtProtectVirtualMemory

__asm__("NtProtectVirtualMemory: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0CD56D1D3 \n\
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

#define ZwFreeVirtualMemory NtFreeVirtualMemory

__asm__("NtFreeVirtualMemory: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0C39D2B0E \n\
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

