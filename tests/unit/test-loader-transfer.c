/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "loader-transfer.h"
#include "test-runner.h"

static void test_loader_prepare_transfer_copies_handoff(void)
{
    struct kbox_loader_handoff handoff;
    struct kbox_loader_transfer_state state;

    memset(&handoff, 0, sizeof(handoff));
    handoff.entry.arch = KBOX_LOADER_ENTRY_ARCH_X86_64;
    handoff.entry.pc = 0x600000100080ULL;
    handoff.entry.sp = 0x70000000fff0ULL;
    handoff.entry.regs[0] = 11;
    handoff.entry.regs[5] = 66;
    handoff.entry_map_start = 0x600000100000ULL;
    handoff.entry_map_end = 0x600000101000ULL;
    handoff.stack_map_start = 0x700000000000ULL;
    handoff.stack_map_end = 0x700000010000ULL;

    ASSERT_EQ(kbox_loader_prepare_transfer(&handoff, &state), 0);
    ASSERT_EQ(state.arch, handoff.entry.arch);
    ASSERT_EQ(state.pc, handoff.entry.pc);
    ASSERT_EQ(state.sp, handoff.entry.sp);
    ASSERT_EQ(state.regs[0], 11);
    ASSERT_EQ(state.regs[5], 66);
    ASSERT_EQ(state.entry_map_start, handoff.entry_map_start);
    ASSERT_EQ(state.entry_map_end, handoff.entry_map_end);
    ASSERT_EQ(state.stack_map_start, handoff.stack_map_start);
    ASSERT_EQ(state.stack_map_end, handoff.stack_map_end);
}

static void test_loader_prepare_transfer_rejects_unmapped_pc(void)
{
    struct kbox_loader_handoff handoff;
    struct kbox_loader_transfer_state state;

    memset(&handoff, 0, sizeof(handoff));
    handoff.entry.arch = KBOX_LOADER_ENTRY_ARCH_AARCH64;
    handoff.entry.pc = 0x5000;
    handoff.entry.sp = 0x8ff0;
    handoff.entry_map_start = 0x6000;
    handoff.entry_map_end = 0x7000;
    handoff.stack_map_start = 0x8000;
    handoff.stack_map_end = 0x9000;

    ASSERT_EQ(kbox_loader_prepare_transfer(&handoff, &state), -1);
}

static void test_loader_prepare_transfer_rejects_misaligned_sp(void)
{
    struct kbox_loader_handoff handoff;
    struct kbox_loader_transfer_state state;

    memset(&handoff, 0, sizeof(handoff));
    handoff.entry.arch = KBOX_LOADER_ENTRY_ARCH_X86_64;
    handoff.entry.pc = 0x6008;
    handoff.entry.sp = 0x8ff8;
    handoff.entry_map_start = 0x6000;
    handoff.entry_map_end = 0x7000;
    handoff.stack_map_start = 0x8000;
    handoff.stack_map_end = 0x9000;

    ASSERT_EQ(kbox_loader_prepare_transfer(&handoff, &state), -1);
}

void test_loader_transfer_init(void)
{
    TEST_REGISTER(test_loader_prepare_transfer_copies_handoff);
    TEST_REGISTER(test_loader_prepare_transfer_rejects_unmapped_pc);
    TEST_REGISTER(test_loader_prepare_transfer_rejects_misaligned_sp);
}
