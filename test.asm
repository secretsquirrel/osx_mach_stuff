; chapter_7, exits when rbp is not 0

global _main

_main:

mov rbp, 0

up:
cmp rbp,0
je up
; quit the program
mov rax, 0x2000001 ; system call $1 with $0x2000000 offset
mov ebx, 0         ; set the exit code to be $0
syscall
