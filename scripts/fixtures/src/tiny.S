# Freestanding x86-64 fixture: no libc, no PLT, hand-written code.
        .text
        .globl _start
        .type _start, @function
_start:
        xor     %edi, %edi
        call    compute
        mov     %eax, %edi
        mov     $60, %eax
        syscall
        .size _start, .-_start

        .type compute, @function
compute:
        push    %rbp
        mov     %rsp, %rbp
        mov     $10, %ecx
        xor     %eax, %eax
1:      add     %ecx, %eax
        dec     %ecx
        jnz     1b
        pop     %rbp
        ret
        .size compute, .-compute
        .section .note.GNU-stack,"",@progbits
