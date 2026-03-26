/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "loader-image.h"
#include "test-runner.h"

#define ET_DYN 3
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
                     uint32_t flags,
                     uint64_t offset,
                     uint64_t vaddr,
                     uint64_t filesz,
                     uint64_t memsz,
                     uint64_t align)
{
    unsigned char *ph = buf + 64 + index * 56;

    set_le32(ph + 0, PT_LOAD);
    set_le32(ph + 4, flags);
    set_le64(ph + 8, offset);
    set_le64(ph + 16, vaddr);
    set_le64(ph + 32, filesz);
    set_le64(ph + 40, memsz);
    set_le64(ph + 48, align);
}

static void build_rx_pie(unsigned char *elf, size_t elf_size)
{
    init_elf64(elf, elf_size, 0x3e, 0x80, 1);
    set_phdr(elf, 0, PF_R | PF_X, 0, 0, 0x180, 0x180, 0x1000);
}

static void build_rw_bss_pie(unsigned char *elf, size_t elf_size)
{
    init_elf64(elf, elf_size, 0x3e, 0x40, 1);
    set_phdr(elf, 0, PF_R | PF_W, 0, 0, 0x180, 0x2500, 0x1000);
}

static void test_loader_materialize_image_maps_main_bytes(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char elf[2048];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec layout_spec;
    struct kbox_loader_image image;
    struct kbox_loader_image_spec image_spec;
    const unsigned char *mapped;

    build_rx_pie(elf, sizeof(elf));
    memset(&layout, 0, sizeof(layout));
    memset(&layout_spec, 0, sizeof(layout_spec));
    memset(&image, 0, sizeof(image));
    memset(&image_spec, 0, sizeof(image_spec));

    layout_spec.main_elf = elf;
    layout_spec.main_elf_len = sizeof(elf);
    layout_spec.argv = argv;
    layout_spec.argc = 1;
    layout_spec.page_size = 4096;
    layout_spec.main_load_bias = 0x600100000000ULL;
    layout_spec.stack_top = 0x700100010000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&layout_spec, &layout), 0);

    image_spec.layout = &layout;
    image_spec.main_elf = elf;
    image_spec.main_elf_len = sizeof(elf);
    ASSERT_EQ(kbox_loader_materialize_image(&image_spec, &image), 0);
    ASSERT_EQ(image.region_count, 2);

    mapped = (const unsigned char *) (uintptr_t) layout.mappings[0].addr;
    ASSERT_EQ(memcmp(mapped, elf, 0x180), 0);
    ASSERT_EQ(mapped[0x17f], elf[0x17f]);

    kbox_loader_image_reset(&image);
    kbox_loader_layout_reset(&layout);
}

static void test_loader_materialize_image_realizes_bss_and_stack(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char elf[4096];
    struct kbox_loader_layout layout;
    struct kbox_loader_layout_spec layout_spec;
    struct kbox_loader_image image;
    struct kbox_loader_image_spec image_spec;
    const unsigned char *mapped;
    const uint64_t *stack_words;

    build_rw_bss_pie(elf, sizeof(elf));
    memset(&layout, 0, sizeof(layout));
    memset(&layout_spec, 0, sizeof(layout_spec));
    memset(&image, 0, sizeof(image));
    memset(&image_spec, 0, sizeof(image_spec));

    layout_spec.main_elf = elf;
    layout_spec.main_elf_len = sizeof(elf);
    layout_spec.argv = argv;
    layout_spec.argc = 1;
    layout_spec.page_size = 4096;
    layout_spec.main_load_bias = 0x600200000000ULL;
    layout_spec.stack_top = 0x700200010000ULL;

    ASSERT_EQ(kbox_loader_build_layout(&layout_spec, &layout), 0);

    image_spec.layout = &layout;
    image_spec.main_elf = elf;
    image_spec.main_elf_len = sizeof(elf);
    ASSERT_EQ(kbox_loader_materialize_image(&image_spec, &image), 0);
    ASSERT_EQ(image.region_count, 3);

    mapped = (const unsigned char *) (uintptr_t) layout.mappings[0].addr;
    ASSERT_EQ(memcmp(mapped, elf, 0x180), 0);
    ASSERT_EQ(mapped[0x180], 0);
    ASSERT_EQ(mapped[0xfff], 0);
    ASSERT_EQ(*((const unsigned char *) (uintptr_t) layout.mappings[1].addr),
              0);

    stack_words = (const uint64_t *) (uintptr_t) layout.initial_sp;
    ASSERT_EQ(stack_words[0], 1);

    kbox_loader_image_reset(&image);
    kbox_loader_layout_reset(&layout);
}

void test_loader_image_init(void)
{
    TEST_REGISTER(test_loader_materialize_image_maps_main_bytes);
    TEST_REGISTER(test_loader_materialize_image_realizes_bss_and_stack);
}
