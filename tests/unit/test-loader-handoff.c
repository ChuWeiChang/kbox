/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "loader-handoff.h"
#include "test-runner.h"

#define ET_DYN 3
#define PT_INTERP 3
#define PT_LOAD 1
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
                       uint16_t machine,
                       uint64_t entry,
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
    set_le16(buf + 16, ET_DYN);
    set_le16(buf + 18, machine);
    set_le32(buf + 20, 1);
    set_le64(buf + 24, entry);
    set_le64(buf + 32, 64);
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

static void build_main_pie(unsigned char *elf,
                           size_t elf_size,
                           uint16_t machine)
{
    init_elf64(elf, elf_size, machine, 0x80, 2);
    set_phdr(elf, 0, PT_LOAD, PF_R | PF_X, 0, 0, 0x200, 0x200, 0x1000);
    set_phdr(elf, 1, PT_INTERP, PF_R, 0x200, 0, 0x20, 0x20, 1);
}

static void build_interp_pie(unsigned char *elf,
                             size_t elf_size,
                             uint16_t machine)
{
    init_elf64(elf, elf_size, machine, 0x140, 1);
    set_phdr(elf, 0, PT_LOAD, PF_R | PF_X, 0, 0, 0x200, 0x200, 0x1000);
}

static void test_loader_build_handoff_main_entry_x86_64(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char elf[2048];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec layout_spec;
    struct kbox_loader_image image;
    struct kbox_loader_image_spec image_spec;
    struct kbox_loader_handoff handoff;

    build_main_pie(elf, sizeof(elf), 0x3e);
    memset(&layout, 0, sizeof(layout));
    memset(&layout_spec, 0, sizeof(layout_spec));
    memset(&image, 0, sizeof(image));
    memset(&image_spec, 0, sizeof(image_spec));

    layout_spec.main_elf = elf;
    layout_spec.main_elf_len = sizeof(elf);
    layout_spec.argv = argv;
    layout_spec.argc = 1;
    layout_spec.page_size = 4096;
    layout_spec.main_load_bias = 0x600300000000ULL;
    layout_spec.stack_top = 0x700300010000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&layout_spec, &layout), 0);
    image_spec.layout = &layout;
    image_spec.main_elf = elf;
    image_spec.main_elf_len = sizeof(elf);
    ASSERT_EQ(kbox_loader_materialize_image(&image_spec, &image), 0);

    ASSERT_EQ(kbox_loader_build_handoff(&layout, &image, &handoff), 0);
    ASSERT_EQ(handoff.entry.arch, KBOX_LOADER_ENTRY_ARCH_X86_64);
    ASSERT_EQ(handoff.entry.pc, layout.initial_pc);
    ASSERT_EQ(handoff.entry.sp, layout.initial_sp);
    ASSERT_EQ(handoff.entry_mapping_index, 0);
    ASSERT_EQ(handoff.stack_mapping_index, layout.mapping_count - 1);
    ASSERT_EQ(handoff.entry_map_start, layout.mappings[0].addr);
    ASSERT_EQ(handoff.entry_map_end,
              layout.mappings[0].addr + layout.mappings[0].size);

    kbox_loader_image_reset(&image);
    kbox_loader_layout_reset(&layout);
}

static void test_loader_build_handoff_dynamic_aarch64_uses_interp_entry(void)
{
    static const char *const argv[] = {"/lib/ld-musl-aarch64.so.1", "sh"};
    unsigned char main_elf[2048];
    unsigned char interp_elf[2048];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec layout_spec;
    struct kbox_loader_image image;
    struct kbox_loader_image_spec image_spec;
    struct kbox_loader_handoff handoff;

    build_main_pie(main_elf, sizeof(main_elf), 0xb7);
    build_interp_pie(interp_elf, sizeof(interp_elf), 0xb7);
    memcpy(main_elf + 0x200, "/lib/ld-musl-aarch64.so.1", 26);
    memset(&layout, 0, sizeof(layout));
    memset(&layout_spec, 0, sizeof(layout_spec));
    memset(&image, 0, sizeof(image));
    memset(&image_spec, 0, sizeof(image_spec));

    layout_spec.main_elf = main_elf;
    layout_spec.main_elf_len = sizeof(main_elf);
    layout_spec.interp_elf = interp_elf;
    layout_spec.interp_elf_len = sizeof(interp_elf);
    layout_spec.argv = argv;
    layout_spec.argc = 2;
    layout_spec.page_size = 4096;
    layout_spec.main_load_bias = 0x600400000000ULL;
    layout_spec.interp_load_bias = 0x600500000000ULL;
    layout_spec.stack_top = 0x700400010000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&layout_spec, &layout), 0);
    image_spec.layout = &layout;
    image_spec.main_elf = main_elf;
    image_spec.main_elf_len = sizeof(main_elf);
    image_spec.interp_elf = interp_elf;
    image_spec.interp_elf_len = sizeof(interp_elf);
    ASSERT_EQ(kbox_loader_materialize_image(&image_spec, &image), 0);

    ASSERT_EQ(kbox_loader_build_handoff(&layout, &image, &handoff), 0);
    ASSERT_EQ(handoff.entry.arch, KBOX_LOADER_ENTRY_ARCH_AARCH64);
    ASSERT_EQ(handoff.entry.pc, layout.initial_pc);
    ASSERT_EQ(handoff.entry_mapping_index, 1);
    ASSERT_EQ(handoff.entry_map_start, layout.mappings[1].addr);

    kbox_loader_image_reset(&image);
    kbox_loader_layout_reset(&layout);
}

static void test_loader_build_handoff_rejects_unmapped_entry(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char elf[2048];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec layout_spec;
    struct kbox_loader_image image;
    struct kbox_loader_image_spec image_spec;
    struct kbox_loader_handoff handoff;

    build_main_pie(elf, sizeof(elf), 0x3e);
    memset(&layout, 0, sizeof(layout));
    memset(&layout_spec, 0, sizeof(layout_spec));
    memset(&image, 0, sizeof(image));
    memset(&image_spec, 0, sizeof(image_spec));

    layout_spec.main_elf = elf;
    layout_spec.main_elf_len = sizeof(elf);
    layout_spec.argv = argv;
    layout_spec.argc = 1;
    layout_spec.page_size = 4096;
    layout_spec.main_load_bias = 0x600600000000ULL;
    layout_spec.stack_top = 0x700600010000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&layout_spec, &layout), 0);
    image_spec.layout = &layout;
    image_spec.main_elf = elf;
    image_spec.main_elf_len = sizeof(elf);
    ASSERT_EQ(kbox_loader_materialize_image(&image_spec, &image), 0);

    layout.initial_pc = layout.mappings[layout.mapping_count - 1].addr;
    ASSERT_EQ(kbox_loader_build_handoff(&layout, &image, &handoff), -1);

    kbox_loader_image_reset(&image);
    kbox_loader_layout_reset(&layout);
}

void test_loader_handoff_init(void)
{
    TEST_REGISTER(test_loader_build_handoff_main_entry_x86_64);
    TEST_REGISTER(test_loader_build_handoff_dynamic_aarch64_uses_interp_entry);
    TEST_REGISTER(test_loader_build_handoff_rejects_unmapped_entry);
}
