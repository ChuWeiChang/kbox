/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "loader-entry.h"
#include "test-runner.h"

#define ET_DYN 3
#define PT_LOAD 1
#define PF_R 0x4
#define PF_X 0x1

static void set_le16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char) (v & 0xff);
    p[1] = (unsigned char) ((v >> 8) & 0xff);
}

static void set_le32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char) (v & 0xff);
    p[1] = (unsigned char) ((v >> 8) & 0xff);
    p[2] = (unsigned char) ((v >> 16) & 0xff);
    p[3] = (unsigned char) ((v >> 24) & 0xff);
}

static void set_le64(unsigned char *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (unsigned char) ((v >> (i * 8)) & 0xff);
}

static void init_elf64(unsigned char *buf,
                       size_t buf_size,
                       uint16_t machine,
                       uint64_t entry)
{
    memset(buf, 0, buf_size);
    buf[0] = 0x7f;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    set_le16(buf + 16, ET_DYN);
    set_le16(buf + 18, machine);
    set_le32(buf + 20, 1);
    set_le64(buf + 24, entry);
    set_le64(buf + 32, 64);
    set_le16(buf + 52, 64);
    set_le16(buf + 54, 56);
    set_le16(buf + 56, 1);
}

static void set_load_phdr(unsigned char *buf, uint64_t filesz)
{
    unsigned char *ph = buf + 64;

    set_le32(ph + 0, PT_LOAD);
    set_le32(ph + 4, PF_R | PF_X);
    set_le64(ph + 8, 0);
    set_le64(ph + 16, 0);
    set_le64(ph + 32, filesz);
    set_le64(ph + 40, filesz);
    set_le64(ph + 48, 0x1000);
}

static void test_loader_build_entry_state_x86_64(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char elf[1024];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec spec;
    struct kbox_loader_entry_state state;

    init_elf64(elf, sizeof(elf), 0x3e, 0x123);
    set_load_phdr(elf, 0x180);
    memset(&layout, 0, sizeof(layout));
    memset(&spec, 0, sizeof(spec));

    spec.main_elf = elf;
    spec.main_elf_len = sizeof(elf);
    spec.argv = argv;
    spec.argc = 1;
    spec.page_size = 4096;
    spec.main_load_bias = 0x610000000000ULL;
    spec.stack_top = 0x710000010000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&spec, &layout), 0);
    ASSERT_EQ(kbox_loader_build_entry_state(&layout, &state), 0);
    ASSERT_EQ(state.arch, KBOX_LOADER_ENTRY_ARCH_X86_64);
    ASSERT_EQ(state.pc, layout.initial_pc);
    ASSERT_EQ(state.sp, layout.initial_sp);
    ASSERT_EQ(state.regs[0], 0);

    kbox_loader_layout_reset(&layout);
}

static void test_loader_build_entry_state_aarch64(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char elf[1024];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec spec;
    struct kbox_loader_entry_state state;

    init_elf64(elf, sizeof(elf), 0xb7, 0x456);
    set_load_phdr(elf, 0x180);
    memset(&layout, 0, sizeof(layout));
    memset(&spec, 0, sizeof(spec));

    spec.main_elf = elf;
    spec.main_elf_len = sizeof(elf);
    spec.argv = argv;
    spec.argc = 1;
    spec.page_size = 4096;
    spec.main_load_bias = 0x620000000000ULL;
    spec.stack_top = 0x720000010000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&spec, &layout), 0);
    ASSERT_EQ(kbox_loader_build_entry_state(&layout, &state), 0);
    ASSERT_EQ(state.arch, KBOX_LOADER_ENTRY_ARCH_AARCH64);
    ASSERT_EQ(state.pc, layout.initial_pc);
    ASSERT_EQ(state.sp, layout.initial_sp);
    ASSERT_EQ(state.regs[5], 0);

    kbox_loader_layout_reset(&layout);
}

static void test_loader_build_entry_state_rejects_unknown_machine(void)
{
    struct kbox_loader_layout layout;
    struct kbox_loader_entry_state state;

    memset(&layout, 0, sizeof(layout));
    layout.main_plan.machine = 0xffff;
    layout.initial_pc = 1;
    layout.initial_sp = 2;

    ASSERT_EQ(kbox_loader_build_entry_state(&layout, &state), -1);
}

void test_loader_entry_init(void)
{
    TEST_REGISTER(test_loader_build_entry_state_x86_64);
    TEST_REGISTER(test_loader_build_entry_state_aarch64);
    TEST_REGISTER(test_loader_build_entry_state_rejects_unknown_machine);
}
