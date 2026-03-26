/* SPDX-License-Identifier: MIT */
#ifndef KBOX_X86_DECODE_H
#define KBOX_X86_DECODE_H

/* Minimal x86-64 instruction length decoder.
 *
 * Walks instruction boundaries in executable segments so the rewrite scanner
 * only matches 0F 05 (syscall) / 0F 34 (sysenter) at true instruction starts,
 * not as embedded bytes inside longer encodings (e.g. immediates, SIB bytes).
 *
 * This is NOT a full disassembler. It decodes only the length of each
 * instruction, which is sufficient for boundary-aware scanning. The decoder
 * handles: legacy prefixes, REX/REX2, VEX (2/3-byte), ModR/M, SIB,
 * displacement, and immediate fields.
 */

#include <stddef.h>
#include <stdint.h>

/* Decode the length of the x86-64 instruction at @code[0..max_len-1].
 * Returns the instruction length in bytes (1..15), or 0 if the instruction
 * could not be decoded (e.g. truncated, invalid encoding).
 *
 * The decoder is conservative: when encountering truly unknown opcodes it
 * returns 0 so the caller can skip one byte and resync (safe: the rewrite
 * scanner treats unknown regions as non-syscall).
 */
int kbox_x86_insn_length(const unsigned char *code, size_t max_len);

#endif /* KBOX_X86_DECODE_H */
