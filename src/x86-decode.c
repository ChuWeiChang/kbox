/* SPDX-License-Identifier: MIT */

/* Minimal x86-64 instruction length decoder.
 *
 * Enough to walk instruction boundaries in executable segments. Not a full
 * disassembler; we only need the length of each instruction so the rewrite
 * scanner can identify 0F 05 / 0F 34 at true instruction starts.
 *
 * Reference: Intel SDM Vol. 2, Chapter 2 "Instruction Format".
 * Instruction layout: [prefixes] [REX] opcode [ModR/M [SIB]] [disp] [imm]
 */

#include "x86-decode.h"

/* Opcode map flags, packed into a single byte per opcode. */
#define F_NONE 0x00   /* No operands (or implicit register-only) */
#define F_MODRM 0x01  /* Has ModR/M byte */
#define F_IMM8 0x02   /* 8-bit immediate */
#define F_IMM32 0x04  /* 32-bit immediate (16-bit with 66h prefix) */
#define F_IMM64 0x08  /* 64-bit immediate (MOV r64, imm64 with REX.W) */
#define F_REL32 0x10  /* 32-bit relative displacement */
#define F_REL8 0x20   /* 8-bit relative displacement */
#define F_PREFIX 0x40 /* This is a prefix, not an opcode */
#define F_BAD 0x80    /* Invalid / unknown in 64-bit mode */

/* One-byte opcode map (0x00..0xFF).
 *
 * This table encodes the operand structure of each primary opcode.
 * Group opcodes (F6/F7, FF, etc.) share the same ModR/M flag since the
 * ModR/M.reg field selects the sub-operation but doesn't change the
 * instruction length (with the exception of F6/F7 TEST which adds an
 * immediate; handled as a special case).
 */
static const unsigned char one_byte_map[256] = {
    /* 00-07: ADD r/m, r / ADD r, r/m / ADD AL,imm8 / ADD eAX,imm32 / PUSH ES /
       POP ES */
    [0x00] = F_MODRM,
    [0x01] = F_MODRM,
    [0x02] = F_MODRM,
    [0x03] = F_MODRM,
    [0x04] = F_IMM8,
    [0x05] = F_IMM32,
    [0x06] = F_BAD,
    [0x07] = F_BAD, /* PUSH/POP ES invalid in 64-bit */

    /* 08-0F: OR */
    [0x08] = F_MODRM,
    [0x09] = F_MODRM,
    [0x0A] = F_MODRM,
    [0x0B] = F_MODRM,
    [0x0C] = F_IMM8,
    [0x0D] = F_IMM32,
    [0x0E] = F_BAD,  /* PUSH CS */
    [0x0F] = F_NONE, /* Two-byte escape; handled separately */

    /* 10-17: ADC */
    [0x10] = F_MODRM,
    [0x11] = F_MODRM,
    [0x12] = F_MODRM,
    [0x13] = F_MODRM,
    [0x14] = F_IMM8,
    [0x15] = F_IMM32,
    [0x16] = F_BAD,
    [0x17] = F_BAD,

    /* 18-1F: SBB */
    [0x18] = F_MODRM,
    [0x19] = F_MODRM,
    [0x1A] = F_MODRM,
    [0x1B] = F_MODRM,
    [0x1C] = F_IMM8,
    [0x1D] = F_IMM32,
    [0x1E] = F_BAD,
    [0x1F] = F_BAD,

    /* 20-27: AND */
    [0x20] = F_MODRM,
    [0x21] = F_MODRM,
    [0x22] = F_MODRM,
    [0x23] = F_MODRM,
    [0x24] = F_IMM8,
    [0x25] = F_IMM32,
    [0x26] = F_PREFIX, /* ES override */
    [0x27] = F_BAD,    /* DAA */

    /* 28-2F: SUB */
    [0x28] = F_MODRM,
    [0x29] = F_MODRM,
    [0x2A] = F_MODRM,
    [0x2B] = F_MODRM,
    [0x2C] = F_IMM8,
    [0x2D] = F_IMM32,
    [0x2E] = F_PREFIX, /* CS override */
    [0x2F] = F_BAD,    /* DAS */

    /* 30-37: XOR */
    [0x30] = F_MODRM,
    [0x31] = F_MODRM,
    [0x32] = F_MODRM,
    [0x33] = F_MODRM,
    [0x34] = F_IMM8,
    [0x35] = F_IMM32,
    [0x36] = F_PREFIX, /* SS override */
    [0x37] = F_BAD,    /* AAA */

    /* 38-3F: CMP */
    [0x38] = F_MODRM,
    [0x39] = F_MODRM,
    [0x3A] = F_MODRM,
    [0x3B] = F_MODRM,
    [0x3C] = F_IMM8,
    [0x3D] = F_IMM32,
    [0x3E] = F_PREFIX, /* DS override */
    [0x3F] = F_BAD,    /* AAS */

    /* 40-4F: REX prefixes in 64-bit mode */
    [0x40] = F_PREFIX,
    [0x41] = F_PREFIX,
    [0x42] = F_PREFIX,
    [0x43] = F_PREFIX,
    [0x44] = F_PREFIX,
    [0x45] = F_PREFIX,
    [0x46] = F_PREFIX,
    [0x47] = F_PREFIX,
    [0x48] = F_PREFIX,
    [0x49] = F_PREFIX,
    [0x4A] = F_PREFIX,
    [0x4B] = F_PREFIX,
    [0x4C] = F_PREFIX,
    [0x4D] = F_PREFIX,
    [0x4E] = F_PREFIX,
    [0x4F] = F_PREFIX,

    /* 50-5F: PUSH/POP r64 */
    [0x50] = F_NONE,
    [0x51] = F_NONE,
    [0x52] = F_NONE,
    [0x53] = F_NONE,
    [0x54] = F_NONE,
    [0x55] = F_NONE,
    [0x56] = F_NONE,
    [0x57] = F_NONE,
    [0x58] = F_NONE,
    [0x59] = F_NONE,
    [0x5A] = F_NONE,
    [0x5B] = F_NONE,
    [0x5C] = F_NONE,
    [0x5D] = F_NONE,
    [0x5E] = F_NONE,
    [0x5F] = F_NONE,

    /* 60-6F */
    [0x60] = F_BAD,
    [0x61] = F_BAD,   /* PUSHA/POPA invalid */
    [0x62] = F_BAD,   /* BOUND invalid (EVEX prefix) */
    [0x63] = F_MODRM, /* MOVSXD */
    [0x64] = F_PREFIX,
    [0x65] = F_PREFIX,          /* FS/GS override */
    [0x66] = F_PREFIX,          /* Operand-size override */
    [0x67] = F_PREFIX,          /* Address-size override */
    [0x68] = F_IMM32,           /* PUSH imm32 */
    [0x69] = F_MODRM | F_IMM32, /* IMUL r, r/m, imm32 */
    [0x6A] = F_IMM8,            /* PUSH imm8 */
    [0x6B] = F_MODRM | F_IMM8,  /* IMUL r, r/m, imm8 */
    [0x6C] = F_NONE,
    [0x6D] = F_NONE, /* INS */
    [0x6E] = F_NONE,
    [0x6F] = F_NONE, /* OUTS */

    /* 70-7F: Jcc rel8 */
    [0x70] = F_REL8,
    [0x71] = F_REL8,
    [0x72] = F_REL8,
    [0x73] = F_REL8,
    [0x74] = F_REL8,
    [0x75] = F_REL8,
    [0x76] = F_REL8,
    [0x77] = F_REL8,
    [0x78] = F_REL8,
    [0x79] = F_REL8,
    [0x7A] = F_REL8,
    [0x7B] = F_REL8,
    [0x7C] = F_REL8,
    [0x7D] = F_REL8,
    [0x7E] = F_REL8,
    [0x7F] = F_REL8,

    /* 80-83: Group 1 (ALU imm) */
    [0x80] = F_MODRM | F_IMM8,
    [0x81] = F_MODRM | F_IMM32,
    [0x82] = F_BAD, /* Invalid in 64-bit */
    [0x83] = F_MODRM | F_IMM8,

    /* 84-8F */
    [0x84] = F_MODRM,
    [0x85] = F_MODRM, /* TEST */
    [0x86] = F_MODRM,
    [0x87] = F_MODRM, /* XCHG */
    [0x88] = F_MODRM,
    [0x89] = F_MODRM, /* MOV r/m, r */
    [0x8A] = F_MODRM,
    [0x8B] = F_MODRM, /* MOV r, r/m */
    [0x8C] = F_MODRM,
    [0x8D] = F_MODRM, /* MOV r/m, Sreg / LEA */
    [0x8E] = F_MODRM, /* MOV Sreg, r/m */
    [0x8F] = F_MODRM, /* POP r/m */

    /* 90-97: XCHG rAX, r / NOP */
    [0x90] = F_NONE,
    [0x91] = F_NONE,
    [0x92] = F_NONE,
    [0x93] = F_NONE,
    [0x94] = F_NONE,
    [0x95] = F_NONE,
    [0x96] = F_NONE,
    [0x97] = F_NONE,

    /* 98-9F */
    [0x98] = F_NONE, /* CBW/CWDE/CDQE */
    [0x99] = F_NONE, /* CWD/CDQ/CQO */
    [0x9A] = F_BAD,  /* CALLF invalid */
    [0x9B] = F_NONE, /* FWAIT */
    [0x9C] = F_NONE, /* PUSHF */
    [0x9D] = F_NONE, /* POPF */
    [0x9E] = F_NONE, /* SAHF */
    [0x9F] = F_NONE, /* LAHF */

    /* A0-AF */
    [0xA0] = F_NONE, /* MOV AL, moffs (special case: 8 or 4 byte addr) */
    [0xA1] = F_NONE, /* MOV rAX, moffs (special case) */
    [0xA2] = F_NONE, /* MOV moffs, AL (special case) */
    [0xA3] = F_NONE, /* MOV moffs, rAX (special case) */
    [0xA4] = F_NONE,
    [0xA5] = F_NONE, /* MOVS */
    [0xA6] = F_NONE,
    [0xA7] = F_NONE, /* CMPS */
    [0xA8] = F_IMM8,
    [0xA9] = F_IMM32, /* TEST AL/rAX, imm */
    [0xAA] = F_NONE,
    [0xAB] = F_NONE, /* STOS */
    [0xAC] = F_NONE,
    [0xAD] = F_NONE, /* LODS */
    [0xAE] = F_NONE,
    [0xAF] = F_NONE, /* SCAS */

    /* B0-BF: MOV r8/r64, imm */
    [0xB0] = F_IMM8,
    [0xB1] = F_IMM8,
    [0xB2] = F_IMM8,
    [0xB3] = F_IMM8,
    [0xB4] = F_IMM8,
    [0xB5] = F_IMM8,
    [0xB6] = F_IMM8,
    [0xB7] = F_IMM8,
    [0xB8] = F_IMM32,
    [0xB9] = F_IMM32,
    [0xBA] = F_IMM32,
    [0xBB] = F_IMM32,
    [0xBC] = F_IMM32,
    [0xBD] = F_IMM32,
    [0xBE] = F_IMM32,
    [0xBF] = F_IMM32,

    /* C0-CF */
    [0xC0] = F_MODRM | F_IMM8, /* Shift Group 2 imm8 */
    [0xC1] = F_MODRM | F_IMM8,
    [0xC2] = F_NONE,            /* RET imm16 (special case: 2-byte immediate) */
    [0xC3] = F_NONE,            /* RET */
    [0xC4] = F_BAD,             /* VEX 3-byte prefix; handled separately */
    [0xC5] = F_BAD,             /* VEX 2-byte prefix; handled separately */
    [0xC6] = F_MODRM | F_IMM8,  /* MOV r/m8, imm8 */
    [0xC7] = F_MODRM | F_IMM32, /* MOV r/m32, imm32 */
    [0xC8] = F_NONE,            /* ENTER: iw, ib (3 bytes, special case) */
    [0xC9] = F_NONE,            /* LEAVE */
    [0xCA] = F_NONE,            /* RETF imm16 (special case) */
    [0xCB] = F_NONE,            /* RETF */
    [0xCC] = F_NONE,            /* INT 3 */
    [0xCD] = F_IMM8,            /* INT imm8 */
    [0xCE] = F_BAD,             /* INTO invalid */
    [0xCF] = F_NONE,            /* IRET */

    /* D0-DF */
    [0xD0] = F_MODRM,
    [0xD1] = F_MODRM, /* Shift Group 2 (1/CL) */
    [0xD2] = F_MODRM,
    [0xD3] = F_MODRM,
    [0xD4] = F_BAD,
    [0xD5] = F_BAD,  /* AAM/AAD invalid */
    [0xD6] = F_BAD,  /* SALC invalid */
    [0xD7] = F_NONE, /* XLAT */
    /* D8-DF: x87 FPU */
    [0xD8] = F_MODRM,
    [0xD9] = F_MODRM,
    [0xDA] = F_MODRM,
    [0xDB] = F_MODRM,
    [0xDC] = F_MODRM,
    [0xDD] = F_MODRM,
    [0xDE] = F_MODRM,
    [0xDF] = F_MODRM,

    /* E0-EF */
    [0xE0] = F_REL8,
    [0xE1] = F_REL8,
    [0xE2] = F_REL8, /* LOOP/LOOPZ/LOOPNZ */
    [0xE3] = F_REL8, /* JRCXZ */
    [0xE4] = F_IMM8,
    [0xE5] = F_IMM8, /* IN imm8 */
    [0xE6] = F_IMM8,
    [0xE7] = F_IMM8,  /* OUT imm8 */
    [0xE8] = F_REL32, /* CALL rel32 */
    [0xE9] = F_REL32, /* JMP rel32 */
    [0xEA] = F_BAD,   /* JMPF invalid */
    [0xEB] = F_REL8,  /* JMP rel8 */
    [0xEC] = F_NONE,
    [0xED] = F_NONE, /* IN DX */
    [0xEE] = F_NONE,
    [0xEF] = F_NONE, /* OUT DX */

    /* F0-FF */
    [0xF0] = F_PREFIX, /* LOCK */
    [0xF1] = F_NONE,   /* INT1/ICEBP */
    [0xF2] = F_PREFIX, /* REPNE */
    [0xF3] = F_PREFIX, /* REP/REPE */
    [0xF4] = F_NONE,   /* HLT */
    [0xF5] = F_NONE,   /* CMC */
    [0xF6] = F_MODRM,  /* Group 3 byte: TEST variant adds imm8 (special case) */
    [0xF7] = F_MODRM, /* Group 3 word: TEST variant adds imm32 (special case) */
    [0xF8] = F_NONE,
    [0xF9] = F_NONE, /* CLC/STC */
    [0xFA] = F_NONE,
    [0xFB] = F_NONE, /* CLI/STI */
    [0xFC] = F_NONE,
    [0xFD] = F_NONE,  /* CLD/STD */
    [0xFE] = F_MODRM, /* Group 4 (INC/DEC r/m8) */
    [0xFF] = F_MODRM, /* Group 5 (INC/DEC/CALL/JMP/PUSH r/m) */
};

/* Two-byte opcode map (0F xx).
 *
 * Flags indicate ModR/M and immediate requirements for each 0F-prefixed
 * opcode. Most SSE/SSE2 instructions have ModR/M; a few have immediates.
 */
static const unsigned char two_byte_map[256] = {
    /* 0F 00-0F */
    [0x00] = F_MODRM, /* Group 6 (SLDT, STR, ...) */
    [0x01] = F_MODRM, /* Group 7 (SGDT, SIDT, ...) */
    [0x02] = F_MODRM, /* LAR */
    [0x03] = F_MODRM, /* LSL */
    [0x04] = F_BAD,
    [0x05] = F_NONE, /* SYSCALL */
    [0x06] = F_NONE, /* CLTS */
    [0x07] = F_NONE, /* SYSRET */
    [0x08] = F_NONE, /* INVD */
    [0x09] = F_NONE, /* WBINVD */
    [0x0A] = F_BAD,
    [0x0B] = F_NONE, /* UD2 */
    [0x0C] = F_BAD,
    [0x0D] = F_MODRM,          /* prefetchw */
    [0x0E] = F_NONE,           /* FEMMS */
    [0x0F] = F_MODRM | F_IMM8, /* 3DNow! */

    /* 0F 10-1F: SSE MOV* */
    [0x10] = F_MODRM,
    [0x11] = F_MODRM,
    [0x12] = F_MODRM,
    [0x13] = F_MODRM,
    [0x14] = F_MODRM,
    [0x15] = F_MODRM,
    [0x16] = F_MODRM,
    [0x17] = F_MODRM,
    [0x18] = F_MODRM, /* prefetch group */
    [0x19] = F_MODRM, /* NOP r/m (multi-byte NOP) */
    [0x1A] = F_MODRM,
    [0x1B] = F_MODRM,
    [0x1C] = F_MODRM,
    [0x1D] = F_MODRM,
    [0x1E] = F_MODRM,
    [0x1F] = F_MODRM, /* NOP r/m (multi-byte NOP) */

    /* 0F 20-2F */
    [0x20] = F_MODRM,
    [0x21] = F_MODRM, /* MOV from/to CRn/DRn */
    [0x22] = F_MODRM,
    [0x23] = F_MODRM,
    [0x24] = F_BAD,
    [0x25] = F_BAD,
    [0x26] = F_BAD,
    [0x27] = F_BAD,
    [0x28] = F_MODRM,
    [0x29] = F_MODRM, /* MOVAPS */
    [0x2A] = F_MODRM,
    [0x2B] = F_MODRM,
    [0x2C] = F_MODRM,
    [0x2D] = F_MODRM,
    [0x2E] = F_MODRM,
    [0x2F] = F_MODRM,

    /* 0F 30-3F */
    [0x30] = F_NONE, /* WRMSR */
    [0x31] = F_NONE, /* RDTSC */
    [0x32] = F_NONE, /* RDMSR */
    [0x33] = F_NONE, /* RDPMC */
    [0x34] = F_NONE, /* SYSENTER */
    [0x35] = F_NONE, /* SYSEXIT */
    [0x36] = F_BAD,
    [0x37] = F_NONE, /* GETSEC */
    [0x38] = F_BAD,  /* 3-byte escape 0F 38; handled separately */
    [0x39] = F_BAD,
    [0x3A] = F_BAD, /* 3-byte escape 0F 3A; handled separately */
    [0x3B] = F_BAD,
    [0x3C] = F_BAD,
    [0x3D] = F_BAD,
    [0x3E] = F_BAD,
    [0x3F] = F_BAD,

    /* 0F 40-4F: CMOVcc */
    [0x40] = F_MODRM,
    [0x41] = F_MODRM,
    [0x42] = F_MODRM,
    [0x43] = F_MODRM,
    [0x44] = F_MODRM,
    [0x45] = F_MODRM,
    [0x46] = F_MODRM,
    [0x47] = F_MODRM,
    [0x48] = F_MODRM,
    [0x49] = F_MODRM,
    [0x4A] = F_MODRM,
    [0x4B] = F_MODRM,
    [0x4C] = F_MODRM,
    [0x4D] = F_MODRM,
    [0x4E] = F_MODRM,
    [0x4F] = F_MODRM,

    /* 0F 50-5F: SSE arithmetic */
    [0x50] = F_MODRM,
    [0x51] = F_MODRM,
    [0x52] = F_MODRM,
    [0x53] = F_MODRM,
    [0x54] = F_MODRM,
    [0x55] = F_MODRM,
    [0x56] = F_MODRM,
    [0x57] = F_MODRM,
    [0x58] = F_MODRM,
    [0x59] = F_MODRM,
    [0x5A] = F_MODRM,
    [0x5B] = F_MODRM,
    [0x5C] = F_MODRM,
    [0x5D] = F_MODRM,
    [0x5E] = F_MODRM,
    [0x5F] = F_MODRM,

    /* 0F 60-6F: SSE pack/unpack */
    [0x60] = F_MODRM,
    [0x61] = F_MODRM,
    [0x62] = F_MODRM,
    [0x63] = F_MODRM,
    [0x64] = F_MODRM,
    [0x65] = F_MODRM,
    [0x66] = F_MODRM,
    [0x67] = F_MODRM,
    [0x68] = F_MODRM,
    [0x69] = F_MODRM,
    [0x6A] = F_MODRM,
    [0x6B] = F_MODRM,
    [0x6C] = F_MODRM,
    [0x6D] = F_MODRM,
    [0x6E] = F_MODRM,
    [0x6F] = F_MODRM,

    /* 0F 70-7F */
    [0x70] = F_MODRM | F_IMM8, /* PSHUFD etc */
    [0x71] = F_MODRM | F_IMM8, /* Group 12 */
    [0x72] = F_MODRM | F_IMM8, /* Group 13 */
    [0x73] = F_MODRM | F_IMM8, /* Group 14 */
    [0x74] = F_MODRM,
    [0x75] = F_MODRM,
    [0x76] = F_MODRM,
    [0x77] = F_NONE, /* EMMS */
    [0x78] = F_MODRM,
    [0x79] = F_MODRM,
    [0x7A] = F_BAD,
    [0x7B] = F_BAD,
    [0x7C] = F_MODRM,
    [0x7D] = F_MODRM,
    [0x7E] = F_MODRM,
    [0x7F] = F_MODRM,

    /* 0F 80-8F: Jcc rel32 */
    [0x80] = F_REL32,
    [0x81] = F_REL32,
    [0x82] = F_REL32,
    [0x83] = F_REL32,
    [0x84] = F_REL32,
    [0x85] = F_REL32,
    [0x86] = F_REL32,
    [0x87] = F_REL32,
    [0x88] = F_REL32,
    [0x89] = F_REL32,
    [0x8A] = F_REL32,
    [0x8B] = F_REL32,
    [0x8C] = F_REL32,
    [0x8D] = F_REL32,
    [0x8E] = F_REL32,
    [0x8F] = F_REL32,

    /* 0F 90-9F: SETcc */
    [0x90] = F_MODRM,
    [0x91] = F_MODRM,
    [0x92] = F_MODRM,
    [0x93] = F_MODRM,
    [0x94] = F_MODRM,
    [0x95] = F_MODRM,
    [0x96] = F_MODRM,
    [0x97] = F_MODRM,
    [0x98] = F_MODRM,
    [0x99] = F_MODRM,
    [0x9A] = F_MODRM,
    [0x9B] = F_MODRM,
    [0x9C] = F_MODRM,
    [0x9D] = F_MODRM,
    [0x9E] = F_MODRM,
    [0x9F] = F_MODRM,

    /* 0F A0-AF */
    [0xA0] = F_NONE,
    [0xA1] = F_NONE,           /* PUSH/POP FS */
    [0xA2] = F_NONE,           /* CPUID */
    [0xA3] = F_MODRM,          /* BT */
    [0xA4] = F_MODRM | F_IMM8, /* SHLD imm8 */
    [0xA5] = F_MODRM,          /* SHLD CL */
    [0xA6] = F_BAD,
    [0xA7] = F_BAD,
    [0xA8] = F_NONE,
    [0xA9] = F_NONE,           /* PUSH/POP GS */
    [0xAA] = F_NONE,           /* RSM */
    [0xAB] = F_MODRM,          /* BTS */
    [0xAC] = F_MODRM | F_IMM8, /* SHRD imm8 */
    [0xAD] = F_MODRM,          /* SHRD CL */
    [0xAE] = F_MODRM,          /* Group 15 (FXSAVE, LFENCE, ...) */
    [0xAF] = F_MODRM,          /* IMUL */

    /* 0F B0-BF */
    [0xB0] = F_MODRM,
    [0xB1] = F_MODRM, /* CMPXCHG */
    [0xB2] = F_MODRM, /* LSS */
    [0xB3] = F_MODRM, /* BTR */
    [0xB4] = F_MODRM,
    [0xB5] = F_MODRM, /* LFS/LGS */
    [0xB6] = F_MODRM,
    [0xB7] = F_MODRM,          /* MOVZX */
    [0xB8] = F_MODRM,          /* POPCNT */
    [0xB9] = F_MODRM,          /* Group 10 (UD1) */
    [0xBA] = F_MODRM | F_IMM8, /* Group 8 (BT/BTS/BTR/BTC imm8) */
    [0xBB] = F_MODRM,          /* BTC */
    [0xBC] = F_MODRM,
    [0xBD] = F_MODRM, /* BSF/BSR, TZCNT/LZCNT */
    [0xBE] = F_MODRM,
    [0xBF] = F_MODRM, /* MOVSX */

    /* 0F C0-CF */
    [0xC0] = F_MODRM,
    [0xC1] = F_MODRM,          /* XADD */
    [0xC2] = F_MODRM | F_IMM8, /* CMPPS/CMPPD */
    [0xC3] = F_MODRM,          /* MOVNTI */
    [0xC4] = F_MODRM | F_IMM8, /* PINSRW */
    [0xC5] = F_MODRM | F_IMM8, /* PEXTRW */
    [0xC6] = F_MODRM | F_IMM8, /* SHUFPS/SHUFPD */
    [0xC7] = F_MODRM,          /* Group 9 (CMPXCHG8B/16B) */
    [0xC8] = F_NONE,
    [0xC9] = F_NONE,
    [0xCA] = F_NONE,
    [0xCB] = F_NONE,
    [0xCC] = F_NONE,
    [0xCD] = F_NONE,
    [0xCE] = F_NONE,
    [0xCF] = F_NONE,
    /* BSWAP r32/r64 */

    /* 0F D0-DF: SSE2 */
    [0xD0] = F_MODRM,
    [0xD1] = F_MODRM,
    [0xD2] = F_MODRM,
    [0xD3] = F_MODRM,
    [0xD4] = F_MODRM,
    [0xD5] = F_MODRM,
    [0xD6] = F_MODRM,
    [0xD7] = F_MODRM,
    [0xD8] = F_MODRM,
    [0xD9] = F_MODRM,
    [0xDA] = F_MODRM,
    [0xDB] = F_MODRM,
    [0xDC] = F_MODRM,
    [0xDD] = F_MODRM,
    [0xDE] = F_MODRM,
    [0xDF] = F_MODRM,

    /* 0F E0-EF: SSE2 */
    [0xE0] = F_MODRM,
    [0xE1] = F_MODRM,
    [0xE2] = F_MODRM,
    [0xE3] = F_MODRM,
    [0xE4] = F_MODRM,
    [0xE5] = F_MODRM,
    [0xE6] = F_MODRM,
    [0xE7] = F_MODRM,
    [0xE8] = F_MODRM,
    [0xE9] = F_MODRM,
    [0xEA] = F_MODRM,
    [0xEB] = F_MODRM,
    [0xEC] = F_MODRM,
    [0xED] = F_MODRM,
    [0xEE] = F_MODRM,
    [0xEF] = F_MODRM,

    /* 0F F0-FF: SSE2 */
    [0xF0] = F_MODRM,
    [0xF1] = F_MODRM,
    [0xF2] = F_MODRM,
    [0xF3] = F_MODRM,
    [0xF4] = F_MODRM,
    [0xF5] = F_MODRM,
    [0xF6] = F_MODRM,
    [0xF7] = F_MODRM,
    [0xF8] = F_MODRM,
    [0xF9] = F_MODRM,
    [0xFA] = F_MODRM,
    [0xFB] = F_MODRM,
    [0xFC] = F_MODRM,
    [0xFD] = F_MODRM,
    [0xFE] = F_MODRM,
    [0xFF] = F_BAD,
};

/* Decode ModR/M + optional SIB + displacement.
 * Returns the number of extra bytes consumed (ModR/M + SIB + displacement),
 * or 0 on truncation.
 */
static int decode_modrm(const unsigned char *code,
                        size_t remaining,
                        int addr_size_32)
{
    unsigned char modrm;
    int mod, rm;
    int len = 1; /* ModR/M byte itself */

    if (remaining < 1)
        return 0;

    modrm = code[0];
    mod = (modrm >> 6) & 3;
    rm = modrm & 7;

    if (mod == 3)
        return 1; /* Register-direct, no displacement */

    /* 32-bit addressing (default in 64-bit mode, or 67h prefix) */
    if (!addr_size_32) {
        /* 64-bit addressing */
        if (mod == 0 && rm == 5) {
            /* RIP-relative: 4-byte displacement */
            return remaining >= 5 ? 5 : 0;
        }
        if (rm == 4) {
            /* SIB byte follows */
            if (remaining < 2)
                return 0;
            len = 2; /* ModR/M + SIB */
            unsigned char sib = code[1];
            int base = sib & 7;
            if (mod == 0 && base == 5) {
                /* disp32 with SIB, no base */
                return remaining >= 6 ? 6 : 0;
            }
        }
        if (mod == 1)
            return remaining >= (size_t) (len + 1) ? len + 1 : 0; /* disp8 */
        if (mod == 2)
            return remaining >= (size_t) (len + 4) ? len + 4 : 0; /* disp32 */
        return remaining >= (size_t) len ? len : 0;
    }

    /* 32-bit addressing mode (with 67h prefix) */
    if (mod == 0 && rm == 5) {
        return remaining >= 5 ? 5 : 0; /* disp32 */
    }
    if (rm == 4) {
        if (remaining < 2)
            return 0;
        len = 2;
        unsigned char sib = code[1];
        int base = sib & 7;
        if (mod == 0 && base == 5)
            return remaining >= 6 ? 6 : 0;
    }
    if (mod == 1)
        return remaining >= (size_t) (len + 1) ? len + 1 : 0;
    if (mod == 2)
        return remaining >= (size_t) (len + 4) ? len + 4 : 0;
    return remaining >= (size_t) len ? len : 0;
}

int kbox_x86_insn_length(const unsigned char *code, size_t max_len)
{
    size_t pos = 0;
    int has_66 = 0;
    int has_67 = 0;
    int has_rex_w = 0;
    unsigned char rex = 0;
    unsigned char opcode;
    unsigned char flags;
    int len;

    if (!code || max_len == 0)
        return 0;

    /* 1. Consume legacy prefixes and REX prefix. */
    for (;;) {
        if (pos >= max_len)
            return 0;
        opcode = code[pos];

        /* Legacy prefixes. A legacy prefix after REX invalidates the REX. */
        if (opcode == 0x26 || opcode == 0x2E || opcode == 0x36 ||
            opcode == 0x3E || opcode == 0x64 || opcode == 0x65 ||
            opcode == 0xF0 || opcode == 0xF2 || opcode == 0xF3) {
            rex = 0;
            has_rex_w = 0;
            pos++;
            continue;
        }
        if (opcode == 0x66) {
            rex = 0;
            has_rex_w = 0;
            has_66 = 1;
            pos++;
            continue;
        }
        if (opcode == 0x67) {
            rex = 0;
            has_rex_w = 0;
            has_67 = 1;
            pos++;
            continue;
        }

        /* REX prefix: 0x40..0x4F. Keep scanning; a following legacy
         * prefix invalidates the REX (cleared above on next iteration).
         */
        if (opcode >= 0x40 && opcode <= 0x4F) {
            rex = opcode;
            has_rex_w = (opcode & 0x08) != 0;
            pos++;
            continue;
        }

        break; /* Not a prefix */
    }

    if (pos >= max_len)
        return 0;
    opcode = code[pos];

    /* 2. Handle VEX prefixes (C4h = 3-byte VEX, C5h = 2-byte VEX).
     * VEX-encoded instructions always have ModR/M. We decode the VEX
     * payload length conservatively.
     */
    if (opcode == 0xC5 && !rex) {
        /* 2-byte VEX: C5 [vvvv] opcode [modrm...] */
        if (pos + 2 >= max_len)
            return 0;
        pos += 2; /* C5 + VEX byte */
        opcode = code[pos];
        pos++;
        flags = two_byte_map[opcode];
        if (flags & F_BAD)
            return 0;
        len = (int) pos;
        if (flags & F_MODRM) {
            int modrm_len = decode_modrm(code + pos, max_len - pos, has_67);
            if (modrm_len == 0)
                return 0;
            len += modrm_len;
        }
        if (flags & F_IMM8)
            len += 1;
        if (flags & F_IMM32)
            len += has_66 ? 2 : 4;
        if (flags & F_REL8)
            len += 1;
        if (flags & F_REL32)
            len += 4;
        return (size_t) len <= max_len ? len : 0;
    }

    if (opcode == 0xC4 && !rex) {
        /* 3-byte VEX: C4 [byte1] [byte2] opcode [modrm...] */
        if (pos + 3 >= max_len)
            return 0;
        unsigned char map_select = code[pos + 1] & 0x1F;
        pos += 3; /* C4 + 2 VEX bytes */
        opcode = code[pos];
        pos++;

        /* map_select 1 = 0F, 2 = 0F38, 3 = 0F3A */
        if (map_select == 1)
            flags = two_byte_map[opcode];
        else if (map_select == 2)
            flags = F_MODRM; /* 0F 38 xx: all have ModR/M, no imm (mostly) */
        else if (map_select == 3)
            flags = F_MODRM | F_IMM8; /* 0F 3A xx: all have ModR/M + imm8 */
        else
            return 0;

        if (flags & F_BAD)
            return 0;
        len = (int) pos;
        if (flags & F_MODRM) {
            int modrm_len = decode_modrm(code + pos, max_len - pos, has_67);
            if (modrm_len == 0)
                return 0;
            len += modrm_len;
        }
        if (flags & F_IMM8)
            len += 1;
        if (flags & F_IMM32)
            len += has_66 ? 2 : 4;
        if (flags & F_REL8)
            len += 1;
        if (flags & F_REL32)
            len += 4;
        return (size_t) len <= max_len ? len : 0;
    }

    /* 3. Two-byte opcode escape (0F xx). */
    if (opcode == 0x0F) {
        pos++;
        if (pos >= max_len)
            return 0;
        unsigned char op2 = code[pos];
        pos++;

        /* 3-byte escape: 0F 38 xx and 0F 3A xx */
        if (op2 == 0x38) {
            if (pos >= max_len)
                return 0;
            pos++; /* consume the third opcode byte */
            /* 0F 38 xx: all have ModR/M, no immediate (SSE3/SSSE3/SSE4.1) */
            len = (int) pos;
            int modrm_len = decode_modrm(code + pos, max_len - pos, has_67);
            if (modrm_len == 0)
                return 0;
            len += modrm_len;
            return (size_t) len <= max_len ? len : 0;
        }
        if (op2 == 0x3A) {
            if (pos >= max_len)
                return 0;
            pos++; /* consume the third opcode byte */
            /* 0F 3A xx: all have ModR/M + imm8 (SSE4.1 PBLENDW etc) */
            len = (int) pos;
            int modrm_len = decode_modrm(code + pos, max_len - pos, has_67);
            if (modrm_len == 0)
                return 0;
            len += modrm_len;
            len += 1; /* imm8 */
            return (size_t) len <= max_len ? len : 0;
        }

        flags = two_byte_map[op2];
        if (flags & F_BAD)
            return 0;

        len = (int) pos;
        if (flags & F_MODRM) {
            int modrm_len = decode_modrm(code + pos, max_len - pos, has_67);
            if (modrm_len == 0)
                return 0;
            len += modrm_len;
        }
        if (flags & F_IMM8)
            len += 1;
        if (flags & F_IMM32)
            len += has_66 ? 2 : 4;
        if (flags & F_REL8)
            len += 1;
        if (flags & F_REL32)
            len += 4;
        return (size_t) len <= max_len ? len : 0;
    }

    /* 4. One-byte opcode. */
    pos++;
    flags = one_byte_map[opcode];

    if (flags & F_PREFIX) {
        /* Stray prefix without a following opcode; treat as 1-byte insn
         * (happens at end of padding regions). */
        return (int) pos;
    }
    if (flags & F_BAD)
        return 0;

    /* Special cases that the flag table can't express cleanly. */

    /* C8h ENTER: iw (2 bytes) + ib (1 byte) = 3 extra bytes */
    if (opcode == 0xC8) {
        len = (int) pos + 3;
        return (size_t) len <= max_len ? len : 0;
    }

    /* C2h / CAh RET/RETF imm16: exactly 2-byte immediate. */
    if (opcode == 0xC2 || opcode == 0xCA) {
        len = (int) pos + 2;
        return (size_t) len <= max_len ? len : 0;
    }

    /* A0-A3: MOV moffs. In 64-bit mode, the address is 8 bytes by default,
     * 4 bytes with 67h address-size override. */
    if (opcode >= 0xA0 && opcode <= 0xA3) {
        len = (int) pos + (has_67 ? 4 : 8);
        return (size_t) len <= max_len ? len : 0;
    }

    /* B8-BF with REX.W: MOV r64, imm64 (10 bytes total). */
    if (opcode >= 0xB8 && opcode <= 0xBF && has_rex_w) {
        len = (int) pos + 8;
        return (size_t) len <= max_len ? len : 0;
    }

    /* F6/F7 Group 3: TEST variant (reg field 0 or 1) has an immediate. */
    if (opcode == 0xF6 || opcode == 0xF7) {
        if (pos >= max_len)
            return 0;
        int modrm_len = decode_modrm(code + pos, max_len - pos, has_67);
        if (modrm_len == 0)
            return 0;
        len = (int) pos + modrm_len;
        int reg_field = (code[pos] >> 3) & 7;
        if (reg_field == 0 || reg_field == 1) {
            /* TEST: has immediate */
            if (opcode == 0xF6)
                len += 1; /* imm8 */
            else
                len += has_66 ? 2 : 4; /* imm16/imm32 */
        }
        return (size_t) len <= max_len ? len : 0;
    }

    len = (int) pos;
    if (flags & F_MODRM) {
        int modrm_len = decode_modrm(code + pos, max_len - pos, has_67);
        if (modrm_len == 0)
            return 0;
        len += modrm_len;
    }
    if (flags & F_IMM8)
        len += 1;
    if (flags & F_IMM32)
        len += has_66 ? 2 : 4;
    if (flags & F_IMM64)
        len += 8;
    if (flags & F_REL8)
        len += 1;
    if (flags & F_REL32)
        len += 4;

    return (size_t) len <= max_len ? len : 0;
}
