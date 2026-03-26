/* SPDX-License-Identifier: MIT */
#include <stdlib.h>
#include <string.h>

#include "loader-layout.h"
#include "test-runner.h"

#define ET_EXEC 2
#define ET_DYN 3
#define PT_LOAD 1
#define PT_INTERP 3
#define PT_PHDR 6
#define PT_GNU_STACK 0x6474e551u
#define PF_R 0x4
#define PF_W 0x2
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
                       uint16_t type,
                       uint16_t machine,
                       uint64_t entry,
                       uint64_t phoff,
                       uint16_t phnum)
{
    memset(buf, 0, buf_size);
    buf[0] = 0x7f;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    set_le16(buf + 16, type);
    set_le16(buf + 18, machine);
    set_le32(buf + 20, 1);
    set_le64(buf + 24, entry);
    set_le64(buf + 32, phoff);
    set_le16(buf + 52, 64);
    set_le16(buf + 54, 56);
    set_le16(buf + 56, phnum);
}

static void set_phdr(unsigned char *buf,
                     size_t index,
                     uint32_t type,
                     uint32_t flags,
                     uint64_t offset,
                     uint64_t vaddr,
                     uint64_t filesz,
                     uint64_t memsz,
                     uint64_t align)
{
    unsigned char *ph = buf + 64 + index * 56;

    set_le32(ph + 0, type);
    set_le32(ph + 4, flags);
    set_le64(ph + 8, offset);
    set_le64(ph + 16, vaddr);
    set_le64(ph + 32, filesz);
    set_le64(ph + 40, memsz);
    set_le64(ph + 48, align);
}

static void build_static_elf(unsigned char *elf, size_t elf_size)
{
    init_elf64(elf, elf_size, ET_EXEC, 0x3e, 0x401000, 64, 1);
    set_phdr(elf, 0, PT_LOAD, PF_R | PF_X, 0, 0x400000, 0x200, 0x300, 0x1000);
}

static void build_dynamic_elf(unsigned char *elf,
                              size_t elf_size,
                              uint16_t machine)
{
    init_elf64(elf, elf_size, ET_DYN, machine, 0x120, 64, 2);
    set_phdr(elf, 0, PT_PHDR, PF_R, 64, 0x40, 112, 112, 8);
    set_phdr(elf, 1, PT_LOAD, PF_R | PF_X, 0, 0, 0x200, 0x200, 0x1000);
}

static void build_bss_heavy_elf(unsigned char *elf, size_t elf_size)
{
    init_elf64(elf, elf_size, ET_EXEC, 0x3e, 0x401000, 64, 1);
    set_phdr(elf, 0, PT_LOAD, PF_R | PF_W, 0, 0x400000, 0x180, 0x2500, 0x1000);
}

static void build_execstack_elf(unsigned char *elf, size_t elf_size)
{
    init_elf64(elf, elf_size, ET_EXEC, 0x3e, 0x401000, 64, 2);
    set_phdr(elf, 0, PT_LOAD, PF_R | PF_X, 0, 0x400000, 0x200, 0x200, 0x1000);
    set_phdr(elf, 1, PT_GNU_STACK, PF_R | PF_W | PF_X, 0, 0, 0, 0, 16);
}

static void build_large_align_interp_elf(unsigned char *elf, size_t elf_size)
{
    init_elf64(elf, elf_size, ET_DYN, 0xb7, 0x696cc, 64, 2);
    set_phdr(elf, 0, PT_LOAD, PF_R | PF_X, 0, 0, 0xa19f4, 0xa19f4, 0x10000);
    set_phdr(elf, 1, PT_LOAD, PF_R | PF_W, 0xafb00, 0xbfb00, 0x904, 0x3410,
             0x10000);
}

static void test_loader_build_layout_static_exec(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char elf[1024];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec spec;

    build_static_elf(elf, sizeof(elf));
    memset(&layout, 0, sizeof(layout));
    memset(&spec, 0, sizeof(spec));

    spec.main_elf = elf;
    spec.main_elf_len = sizeof(elf);
    spec.argv = argv;
    spec.argc = 1;
    spec.page_size = 4096;
    spec.stack_top = 0x700000010000ULL;
    spec.main_load_bias = 0x600000000000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&spec, &layout), 0);
    ASSERT_EQ(layout.has_interp, 0);
    ASSERT_EQ(layout.main_load_bias, 0);
    ASSERT_EQ(layout.initial_pc, 0x401000);
    ASSERT_EQ(layout.initial_sp, layout.stack.initial_sp);
    ASSERT_EQ(layout.stack_size, KBOX_LOADER_DEFAULT_STACK_SIZE);
    ASSERT_EQ(layout.mapping_count, 2);
    ASSERT_EQ(layout.mappings[0].source, KBOX_LOADER_MAPPING_MAIN);
    ASSERT_EQ(layout.mappings[0].addr, 0x400000);
    ASSERT_EQ(layout.mappings[0].size, 0x1000);
    ASSERT_EQ(layout.mappings[0].file_offset, 0);
    ASSERT_EQ(layout.mappings[0].file_size, 0x200);
    ASSERT_EQ(layout.mappings[0].zero_fill_start, 0x400200);
    ASSERT_EQ(layout.mappings[0].zero_fill_size, 0xe00);
    ASSERT_EQ(layout.mappings[0].prot, PROT_READ | PROT_EXEC);
    ASSERT_EQ(layout.mappings[0].flags, MAP_PRIVATE | MAP_FIXED);
    ASSERT_EQ(layout.mappings[1].source, KBOX_LOADER_MAPPING_STACK);
    ASSERT_EQ(layout.mappings[1].addr,
              spec.stack_top - KBOX_LOADER_DEFAULT_STACK_SIZE);
    ASSERT_EQ(layout.mappings[1].prot, PROT_READ | PROT_WRITE);

    kbox_loader_layout_reset(&layout);
}

static void test_loader_build_layout_dynamic_interp_entry(void)
{
    static const char *const argv[] = {"/lib/ld-musl-aarch64.so.1", "sh"};
    unsigned char main_elf[1024];
    unsigned char interp_elf[1024];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec spec;

    build_dynamic_elf(main_elf, sizeof(main_elf), 0xb7);
    build_dynamic_elf(interp_elf, sizeof(interp_elf), 0xb7);
    memset(&layout, 0, sizeof(layout));
    memset(&spec, 0, sizeof(spec));

    spec.main_elf = main_elf;
    spec.main_elf_len = sizeof(main_elf);
    spec.interp_elf = interp_elf;
    spec.interp_elf_len = sizeof(interp_elf);
    spec.argv = argv;
    spec.argc = 2;
    spec.page_size = 4096;
    spec.stack_top = 0x7fff00002000ULL;
    spec.main_load_bias = 0x555500000000ULL;
    spec.interp_load_bias = 0x777700000000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&spec, &layout), 0);
    ASSERT_EQ(layout.has_interp, 1);
    ASSERT_EQ(layout.initial_pc,
              spec.interp_load_bias + layout.interp_plan.entry);
    ASSERT_EQ(layout.main_load_bias, spec.main_load_bias);
    ASSERT_EQ(layout.interp_load_bias, spec.interp_load_bias);
    ASSERT_EQ(layout.mapping_count, 3);
    ASSERT_EQ(layout.mappings[0].source, KBOX_LOADER_MAPPING_MAIN);
    ASSERT_EQ(layout.mappings[0].addr, spec.main_load_bias);
    ASSERT_EQ(layout.mappings[0].zero_fill_size, 0);
    ASSERT_EQ(layout.mappings[1].source, KBOX_LOADER_MAPPING_INTERP);
    ASSERT_EQ(layout.mappings[1].addr, spec.interp_load_bias);
    ASSERT_EQ(layout.mappings[1].zero_fill_size, 0);
    ASSERT_EQ(layout.mappings[2].source, KBOX_LOADER_MAPPING_STACK);

    kbox_loader_layout_reset(&layout);
}

static void test_loader_build_layout_emits_bss_extension_mapping(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char elf[2048];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec spec;

    build_bss_heavy_elf(elf, sizeof(elf));
    memset(&layout, 0, sizeof(layout));
    memset(&spec, 0, sizeof(spec));

    spec.main_elf = elf;
    spec.main_elf_len = sizeof(elf);
    spec.argv = argv;
    spec.argc = 1;
    spec.page_size = 4096;
    spec.stack_top = 0x700000010000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&spec, &layout), 0);
    ASSERT_EQ(layout.mapping_count, 3);
    ASSERT_EQ(layout.mappings[0].source, KBOX_LOADER_MAPPING_MAIN);
    ASSERT_EQ(layout.mappings[0].addr, 0x400000);
    ASSERT_EQ(layout.mappings[0].size, 0x1000);
    ASSERT_EQ(layout.mappings[0].file_offset, 0);
    ASSERT_EQ(layout.mappings[0].file_size, 0x180);
    ASSERT_EQ(layout.mappings[0].zero_fill_start, 0x400180);
    ASSERT_EQ(layout.mappings[0].zero_fill_size, 0xe80);
    ASSERT_EQ(layout.mappings[0].flags, MAP_PRIVATE | MAP_FIXED);
    ASSERT_EQ(layout.mappings[1].source, KBOX_LOADER_MAPPING_MAIN);
    ASSERT_EQ(layout.mappings[1].addr, 0x401000);
    ASSERT_EQ(layout.mappings[1].size, 0x2000);
    ASSERT_EQ(layout.mappings[1].file_size, 0);
    ASSERT_EQ(layout.mappings[1].zero_fill_size, 0);
    ASSERT_EQ(layout.mappings[1].flags,
              MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS);
    ASSERT_EQ(layout.mappings[2].source, KBOX_LOADER_MAPPING_STACK);

    kbox_loader_layout_reset(&layout);
}

static void test_loader_build_layout_rejects_bad_interp(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char main_elf[1024];
    unsigned char interp_elf[64];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec spec;

    build_static_elf(main_elf, sizeof(main_elf));
    memset(interp_elf, 0, sizeof(interp_elf));
    memset(&layout, 0, sizeof(layout));
    memset(&spec, 0, sizeof(spec));

    spec.main_elf = main_elf;
    spec.main_elf_len = sizeof(main_elf);
    spec.interp_elf = interp_elf;
    spec.interp_elf_len = sizeof(interp_elf);
    spec.argv = argv;
    spec.argc = 1;
    spec.page_size = 4096;
    spec.stack_top = 0x700000010000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&spec, &layout), -1);
}

static void test_loader_build_layout_honors_large_segment_align(void)
{
    static const char *const argv[] = {"/lib/ld-musl-aarch64.so.1", "true"};
    unsigned char *interp_elf;
    unsigned char main_elf[1024];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec spec;

    interp_elf = calloc(1, 0xb1000);
    ASSERT_NE(interp_elf, NULL);
    build_dynamic_elf(main_elf, sizeof(main_elf), 0xb7);
    build_large_align_interp_elf(interp_elf, 0xb1000);
    memset(&layout, 0, sizeof(layout));
    memset(&spec, 0, sizeof(spec));

    spec.main_elf = main_elf;
    spec.main_elf_len = sizeof(main_elf);
    spec.interp_elf = interp_elf;
    spec.interp_elf_len = 0xb1000;
    spec.argv = argv;
    spec.argc = 2;
    spec.page_size = 4096;
    spec.stack_top = 0x7fff00002000ULL;
    spec.main_load_bias = 0x600000000000ULL;
    spec.interp_load_bias = 0x610000000000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&spec, &layout), 0);
    ASSERT_EQ(layout.mapping_count, 4);
    ASSERT_EQ(layout.mappings[1].source, KBOX_LOADER_MAPPING_INTERP);
    ASSERT_EQ(layout.mappings[1].addr, spec.interp_load_bias);
    ASSERT_EQ(layout.mappings[1].size, 0xb0000);
    ASSERT_EQ(layout.mappings[2].source, KBOX_LOADER_MAPPING_INTERP);
    ASSERT_EQ(layout.mappings[2].addr, spec.interp_load_bias + 0xb0000);
    ASSERT_EQ(layout.mappings[2].size, 0x20000);
    ASSERT_EQ(layout.mappings[2].file_offset, 0xa0000);
    ASSERT_EQ(layout.mappings[2].file_size, 0x10404);
    ASSERT_EQ(layout.mappings[2].zero_fill_start,
              spec.interp_load_bias + 0xc0404);
    ASSERT_EQ(layout.mappings[2].zero_fill_size, 0xfbfc);
    ASSERT_EQ(layout.mappings[3].source, KBOX_LOADER_MAPPING_STACK);

    kbox_loader_layout_reset(&layout);
    free(interp_elf);
}

static void test_loader_build_layout_honors_exec_stack(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char elf[1024];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec spec;

    build_execstack_elf(elf, sizeof(elf));
    memset(&layout, 0, sizeof(layout));
    memset(&spec, 0, sizeof(spec));

    spec.main_elf = elf;
    spec.main_elf_len = sizeof(elf);
    spec.argv = argv;
    spec.argc = 1;
    spec.page_size = 4096;
    spec.stack_top = 0x700000010000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&spec, &layout), 0);
    ASSERT_EQ(layout.mappings[1].source, KBOX_LOADER_MAPPING_STACK);
    ASSERT_EQ(layout.mappings[1].prot, PROT_READ | PROT_WRITE | PROT_EXEC);

    kbox_loader_layout_reset(&layout);
}

void test_loader_layout_init(void)
{
    TEST_REGISTER(test_loader_build_layout_static_exec);
    TEST_REGISTER(test_loader_build_layout_dynamic_interp_entry);
    TEST_REGISTER(test_loader_build_layout_emits_bss_extension_mapping);
    TEST_REGISTER(test_loader_build_layout_rejects_bad_interp);
    TEST_REGISTER(test_loader_build_layout_honors_large_segment_align);
    TEST_REGISTER(test_loader_build_layout_honors_exec_stack);
}
