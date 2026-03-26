/* SPDX-License-Identifier: MIT */
/* Minimal getpid benchmark -- no libc, no TLS.
 * Prints: "NNNNns\n" (total ns for 10000 getpid calls).
 * Divide by 10000 to get ns/call.
 */
.globl _start
_start:
    /* clock_gettime(CLOCK_MONOTONIC, &t0) */
    sub $16, %rsp
    mov $228, %rax
    mov $1, %rdi
    mov %rsp, %rsi
    syscall
    mov (%rsp), %r12            /* t0.sec */
    mov 8(%rsp), %r13           /* t0.nsec */

    /* 10000 x getpid -- use %rbx as counter (not clobbered by syscall) */
    mov $10000, %ebx
.loop:
    mov $39, %eax
    syscall
    dec %ebx
    jnz .loop

    /* clock_gettime(CLOCK_MONOTONIC, &t1) */
    mov $228, %rax
    mov $1, %rdi
    mov %rsp, %rsi
    syscall
    mov (%rsp), %r14            /* t1.sec */
    mov 8(%rsp), %r15           /* t1.nsec */
    add $16, %rsp

    /* elapsed = (t1.sec - t0.sec)*1e9 + (t1.nsec - t0.nsec) */
    sub %r12, %r14
    imul $1000000000, %r14, %r14
    sub %r13, %r15
    add %r15, %r14              /* r14 = total_ns */

    /* Format r14 as decimal into stack buffer, then write */
    sub $32, %rsp
    lea 30(%rsp), %rdi          /* point to end */
    movb $'\n', (%rdi)
    dec %rdi
    /* Append "ns" */
    movb $'s', (%rdi)
    dec %rdi
    movb $'n', (%rdi)
    dec %rdi

    mov %r14, %rax
    mov $10, %r8
.fmt:
    xor %rdx, %rdx
    div %r8
    add $'0', %dl
    movb %dl, (%rdi)
    dec %rdi
    test %rax, %rax
    jnz .fmt

    /* rdi points one before first digit */
    inc %rdi
    /* length = 31 - (rdi - rsp) */
    lea 31(%rsp), %rdx
    sub %rdi, %rdx              /* len */

    /* write(1, rdi, len) */
    mov %rdi, %rsi
    mov $1, %rdi
    mov $1, %rax
    syscall

    add $32, %rsp

    /* exit(0) */
    mov $60, %rax
    xor %rdi, %rdi
    syscall
