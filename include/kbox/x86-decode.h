/* SPDX-License-Identifier: MIT */
#ifndef KBOX_X86_DECODE_H
#define KBOX_X86_DECODE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Minimal x86-64 instruction length decoder.
 *
 * Used by the rewrite scanner so syscall opcodes are only matched at real
 * instruction boundaries, not inside immediates or other instruction bytes.
 */
int kbox_x86_insn_length(const unsigned char *code, size_t max_len);

#endif /* KBOX_X86_DECODE_H */
