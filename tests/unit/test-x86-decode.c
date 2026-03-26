/* SPDX-License-Identifier: MIT */

#include "../../src/x86-decode.h"
#include "test-runner.h"

static void test_x86_nop(void)
{
    unsigned char buf[] = {0x90};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 1);
}

static void test_x86_ret(void)
{
    unsigned char buf[] = {0xC3};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 1);
}

static void test_x86_push_pop(void)
{
    unsigned char push_rax[] = {0x50};
    unsigned char pop_rbx[] = {0x5B};
    ASSERT_EQ(kbox_x86_insn_length(push_rax, 1), 1);
    ASSERT_EQ(kbox_x86_insn_length(pop_rbx, 1), 1);
}

static void test_x86_rex_push(void)
{
    unsigned char buf[] = {0x48, 0x50};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 2);
}

static void test_x86_syscall(void)
{
    unsigned char buf[] = {0x0F, 0x05};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 2);
}

static void test_x86_sysenter(void)
{
    unsigned char buf[] = {0x0F, 0x34};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 2);
}

static void test_x86_mov_eax_imm32(void)
{
    unsigned char buf[] = {0xB8, 0x01, 0x00, 0x00, 0x00};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 5);
}

static void test_x86_mov_al_imm8(void)
{
    unsigned char buf[] = {0xB0, 0x42};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 2);
}

static void test_x86_movabs_rax_imm64(void)
{
    unsigned char buf[] = {0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 10);
}

static void test_x86_movabs_r11_imm64(void)
{
    unsigned char buf[] = {0x49, 0xBB, 1, 2, 3, 4, 5, 6, 7, 8};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 10);
}

static void test_x86_xor_rax_rax(void)
{
    unsigned char buf[] = {0x48, 0x31, 0xC0};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 3);
}

static void test_x86_mov_rbp_disp8(void)
{
    /* MOV [RBP-8], RAX */
    unsigned char buf[] = {0x48, 0x89, 0x45, 0xF8};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 4);
}

static void test_x86_mov_rsp_sib_disp8(void)
{
    /* MOV [RSP+0x10], RAX -- needs SIB byte */
    unsigned char buf[] = {0x48, 0x89, 0x44, 0x24, 0x10};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 5);
}

static void test_x86_lea_rip_relative(void)
{
    /* LEA RAX, [RIP+disp32] */
    unsigned char buf[] = {0x48, 0x8D, 0x05, 0x00, 0x01, 0x02, 0x03};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 7);
}

static void test_x86_jcc_rel8(void)
{
    unsigned char je[] = {0x74, 0x0A};
    unsigned char jne[] = {0x75, 0x10};
    ASSERT_EQ(kbox_x86_insn_length(je, sizeof(je)), 2);
    ASSERT_EQ(kbox_x86_insn_length(jne, sizeof(jne)), 2);
}

static void test_x86_jcc_rel32(void)
{
    unsigned char buf[] = {0x0F, 0x84, 0x00, 0x01, 0x00, 0x00};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 6);
}

static void test_x86_call_rel32(void)
{
    unsigned char buf[] = {0xE8, 0x00, 0x01, 0x00, 0x00};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 5);
}

static void test_x86_jmp_rel32(void)
{
    unsigned char buf[] = {0xE9, 0x00, 0x01, 0x00, 0x00};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 5);
}

static void test_x86_jmp_rel8(void)
{
    unsigned char buf[] = {0xEB, 0x10};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 2);
}

static void test_x86_group1_imm8(void)
{
    /* ADD [RBP-4], imm8: 83 45 FC 01 */
    unsigned char buf[] = {0x83, 0x45, 0xFC, 0x01};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 4);
}

static void test_x86_group1_imm32(void)
{
    /* ADD [RBP-4], imm32: 81 45 FC 01020304 */
    unsigned char buf[] = {0x81, 0x45, 0xFC, 0x01, 0x02, 0x03, 0x04};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 7);
}

static void test_x86_enter(void)
{
    unsigned char buf[] = {0xC8, 0x00, 0x01, 0x00};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 4);
}

static void test_x86_ret_imm16(void)
{
    unsigned char buf[] = {0xC2, 0x08, 0x00};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 3);
}

static void test_x86_group3_test_imm8(void)
{
    /* TEST [RBP-1], imm8: F6 45 FF 01 */
    unsigned char buf[] = {0xF6, 0x45, 0xFF, 0x01};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 4);
}

static void test_x86_group3_test_imm32(void)
{
    /* TEST EAX, imm32: F7 C0 01020304 */
    unsigned char buf[] = {0xF7, 0xC0, 0x01, 0x02, 0x03, 0x04};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 6);
}

static void test_x86_group3_not(void)
{
    /* NOT EAX: F7 D0 (no immediate) */
    unsigned char buf[] = {0xF7, 0xD0};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 2);
}

static void test_x86_call_rax(void)
{
    /* FF D0 */
    unsigned char buf[] = {0xFF, 0xD0};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 2);
}

static void test_x86_jmp_r10(void)
{
    /* 41 FF E2 */
    unsigned char buf[] = {0x41, 0xFF, 0xE2};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 3);
}

static void test_x86_lock_xchg(void)
{
    /* F0 87 03 */
    unsigned char buf[] = {0xF0, 0x87, 0x03};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 3);
}

static void test_x86_rep_movsb(void)
{
    unsigned char buf[] = {0xF3, 0xA4};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 2);
}

static void test_x86_cpuid(void)
{
    unsigned char buf[] = {0x0F, 0xA2};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 2);
}

static void test_x86_ud2(void)
{
    unsigned char buf[] = {0x0F, 0x0B};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 2);
}

static void test_x86_66_prefix_imm16(void)
{
    /* 66 05 01 02: ADD AX, imm16 */
    unsigned char buf[] = {0x66, 0x05, 0x01, 0x02};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 4);
}

static void test_x86_multi_byte_nop(void)
{
    /* 0F 1F 00: NOP DWORD [RAX] */
    unsigned char nop3[] = {0x0F, 0x1F, 0x00};
    ASSERT_EQ(kbox_x86_insn_length(nop3, sizeof(nop3)), 3);

    /* 0F 1F 40 00: NOP DWORD [RAX+0] */
    unsigned char nop4[] = {0x0F, 0x1F, 0x40, 0x00};
    ASSERT_EQ(kbox_x86_insn_length(nop4, sizeof(nop4)), 4);

    /* 66 0F 1F 44 00 00: 6-byte NOP */
    unsigned char nop6[] = {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00};
    ASSERT_EQ(kbox_x86_insn_length(nop6, sizeof(nop6)), 6);
}

static void test_x86_truncated(void)
{
    unsigned char buf[] = {0x0F};
    ASSERT_EQ(kbox_x86_insn_length(buf, 1), 0);
}

static void test_x86_null_input(void)
{
    ASSERT_EQ(kbox_x86_insn_length(NULL, 10), 0);
}

static void test_x86_zero_len(void)
{
    unsigned char buf[] = {0x90};
    ASSERT_EQ(kbox_x86_insn_length(buf, 0), 0);
}

/* Critical: bytes 0F 05 inside an immediate must NOT look like syscall. */
static void test_x86_false_positive_syscall_in_imm(void)
{
    /* MOV EAX, 0x0000050F: B8 0F 05 00 00 */
    unsigned char mov[] = {0xB8, 0x0F, 0x05, 0x00, 0x00};
    ASSERT_EQ(kbox_x86_insn_length(mov, sizeof(mov)), 5);
}

static void test_x86_false_positive_syscall_in_disp(void)
{
    /* MOV byte [rsp+0x0f], 5: C6 44 24 0F 05 */
    unsigned char mov[] = {0xC6, 0x44, 0x24, 0x0F, 0x05};
    ASSERT_EQ(kbox_x86_insn_length(mov, sizeof(mov)), 5);
}

static void test_x86_3byte_escape_0f38(void)
{
    /* 66 0F 38 00 C1: PSHUFB XMM0, XMM1 */
    unsigned char buf[] = {0x66, 0x0F, 0x38, 0x00, 0xC1};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 5);
}

static void test_x86_3byte_escape_0f3a(void)
{
    /* 66 0F 3A 0F C1 04: PALIGNR XMM0, XMM1, 4 */
    unsigned char buf[] = {0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x04};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 6);
}

static void test_x86_moffs64(void)
{
    /* A1 + 8-byte address */
    unsigned char buf[] = {0xA1, 1, 2, 3, 4, 5, 6, 7, 8};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 9);
}

static void test_x86_moffs32_67(void)
{
    /* 67 A1 + 4-byte address */
    unsigned char buf[] = {0x67, 0xA1, 1, 2, 3, 4};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 6);
}

static void test_x86_bswap(void)
{
    unsigned char bswap32[] = {0x0F, 0xC8};
    unsigned char bswap64[] = {0x48, 0x0F, 0xC8};
    ASSERT_EQ(kbox_x86_insn_length(bswap32, sizeof(bswap32)), 2);
    ASSERT_EQ(kbox_x86_insn_length(bswap64, sizeof(bswap64)), 3);
}

static void test_x86_sib_disp32_no_base(void)
{
    /* MOV EAX, [disp32+RSI*4]: 8B 04 B5 00 10 20 30 */
    unsigned char buf[] = {0x8B, 0x04, 0xB5, 0x00, 0x10, 0x20, 0x30};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 7);
}

static void test_x86_cmovcc(void)
{
    /* 48 0F 44 C1: CMOVE RAX, RCX */
    unsigned char buf[] = {0x48, 0x0F, 0x44, 0xC1};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 4);
}

static void test_x86_bt_imm8(void)
{
    /* 0F BA E0 34: BT EAX, 0x34 (byte 34 could look like sysenter) */
    unsigned char buf[] = {0x0F, 0xBA, 0xE0, 0x34};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 4);
}

/* REX followed by legacy prefix: REX is invalidated. */
static void test_x86_rex_then_lock(void)
{
    /* 48 F0 87 03: ignored-REX, LOCK XCHG [RBX], EAX (4 bytes) */
    unsigned char buf[] = {0x48, 0xF0, 0x87, 0x03};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 4);
}

static void test_x86_rex_then_66(void)
{
    /* 48 66 89 C0: ignored-REX, 66 MOV AX, AX (4 bytes) */
    unsigned char buf[] = {0x48, 0x66, 0x89, 0xC0};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 4);
}

static void test_x86_stray_rex_at_end(void)
{
    unsigned char buf[] = {0x48};
    ASSERT_EQ(kbox_x86_insn_length(buf, 1), 0);
}

static void test_x86_66_group1_imm16(void)
{
    /* 66 81 C0 01 02: ADD AX, imm16 (5 bytes with 66h) */
    unsigned char buf[] = {0x66, 0x81, 0xC0, 0x01, 0x02};
    ASSERT_EQ(kbox_x86_insn_length(buf, sizeof(buf)), 5);
}

void test_x86_decode_init(void)
{
    TEST_REGISTER(test_x86_nop);
    TEST_REGISTER(test_x86_ret);
    TEST_REGISTER(test_x86_push_pop);
    TEST_REGISTER(test_x86_rex_push);
    TEST_REGISTER(test_x86_syscall);
    TEST_REGISTER(test_x86_sysenter);
    TEST_REGISTER(test_x86_mov_eax_imm32);
    TEST_REGISTER(test_x86_mov_al_imm8);
    TEST_REGISTER(test_x86_movabs_rax_imm64);
    TEST_REGISTER(test_x86_movabs_r11_imm64);
    TEST_REGISTER(test_x86_xor_rax_rax);
    TEST_REGISTER(test_x86_mov_rbp_disp8);
    TEST_REGISTER(test_x86_mov_rsp_sib_disp8);
    TEST_REGISTER(test_x86_lea_rip_relative);
    TEST_REGISTER(test_x86_jcc_rel8);
    TEST_REGISTER(test_x86_jcc_rel32);
    TEST_REGISTER(test_x86_call_rel32);
    TEST_REGISTER(test_x86_jmp_rel32);
    TEST_REGISTER(test_x86_jmp_rel8);
    TEST_REGISTER(test_x86_group1_imm8);
    TEST_REGISTER(test_x86_group1_imm32);
    TEST_REGISTER(test_x86_enter);
    TEST_REGISTER(test_x86_ret_imm16);
    TEST_REGISTER(test_x86_group3_test_imm8);
    TEST_REGISTER(test_x86_group3_test_imm32);
    TEST_REGISTER(test_x86_group3_not);
    TEST_REGISTER(test_x86_call_rax);
    TEST_REGISTER(test_x86_jmp_r10);
    TEST_REGISTER(test_x86_lock_xchg);
    TEST_REGISTER(test_x86_rep_movsb);
    TEST_REGISTER(test_x86_cpuid);
    TEST_REGISTER(test_x86_ud2);
    TEST_REGISTER(test_x86_66_prefix_imm16);
    TEST_REGISTER(test_x86_multi_byte_nop);
    TEST_REGISTER(test_x86_truncated);
    TEST_REGISTER(test_x86_null_input);
    TEST_REGISTER(test_x86_zero_len);
    TEST_REGISTER(test_x86_false_positive_syscall_in_imm);
    TEST_REGISTER(test_x86_false_positive_syscall_in_disp);
    TEST_REGISTER(test_x86_3byte_escape_0f38);
    TEST_REGISTER(test_x86_3byte_escape_0f3a);
    TEST_REGISTER(test_x86_moffs64);
    TEST_REGISTER(test_x86_moffs32_67);
    TEST_REGISTER(test_x86_bswap);
    TEST_REGISTER(test_x86_sib_disp32_no_base);
    TEST_REGISTER(test_x86_cmovcc);
    TEST_REGISTER(test_x86_bt_imm8);
    TEST_REGISTER(test_x86_rex_then_lock);
    TEST_REGISTER(test_x86_rex_then_66);
    TEST_REGISTER(test_x86_stray_rex_at_end);
    TEST_REGISTER(test_x86_66_group1_imm16);
}
