/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "kbox/elf.h"
#include "test-runner.h"

/* Minimal 64-bit little-endian ELF with one PT_INTERP program header. */
static const unsigned char elf_with_interp[] = {
    /* ELF header (64 bytes) */
    0x7f,
    'E',
    'L',
    'F', /* magic */
    2,   /* class: 64-bit */
    1,   /* data: little-endian */
    1,   /* version */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* padding */
    2,
    0, /* type: ET_EXEC */
    0x3e,
    0, /* machine: x86_64 */
    1,
    0,
    0,
    0, /* version */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* entry */
    /* phoff = 64 (offset 32..39) */
    64,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* shoff */
    0,
    0,
    0,
    0, /* flags */
    64,
    0, /* ehsize */
    56,
    0, /* phentsize */
    1,
    0, /* phnum = 1 */
    0,
    0, /* shentsize */
    0,
    0, /* shnum */
    0,
    0, /* shstrndx */

    /* Program header (56 bytes) at offset 64 */
    3,
    0,
    0,
    0, /* p_type = PT_INTERP (3) */
    0,
    0,
    0,
    0, /* p_flags */
    /* p_offset = 120 (offset 64+8..64+15) */
    120,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* p_vaddr */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* p_paddr */
    /* p_filesz = 28 (offset 64+32..64+39) */
    28,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* p_memsz */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* p_align */

    /* Interpreter string at offset 120 */
    '/',
    'l',
    'i',
    'b',
    '6',
    '4',
    '/',
    'l',
    'd',
    '-',
    'l',
    'i',
    'n',
    'u',
    'x',
    '-',
    'x',
    '8',
    '6',
    '-',
    '6',
    '4',
    '.',
    's',
    'o',
    '.',
    '2',
    0,
};

/* Static binary: no PT_INTERP */
static const unsigned char elf_static[] = {
    /* ELF header (64 bytes) */
    0x7f,
    'E',
    'L',
    'F',
    2,
    1,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    2,
    0, /* ET_EXEC */
    0x3e,
    0, /* x86_64 */
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* entry */
    64,
    0,
    0,
    0,
    0,
    0,
    0,
    0, /* phoff */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    64,
    0,
    56,
    0,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,

    /* PT_LOAD header (not PT_INTERP) */
    1,
    0,
    0,
    0, /* p_type = PT_LOAD (1) */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
};

static void test_elf_parse_interp(void)
{
    char out[256];
    int len = kbox_parse_elf_interp(elf_with_interp, sizeof(elf_with_interp),
                                    out, sizeof(out));
    ASSERT_TRUE(len > 0);
    ASSERT_STREQ(out, "/lib64/ld-linux-x86-64.so.2");
}

static void test_elf_static_no_interp(void)
{
    char out[256];
    int len =
        kbox_parse_elf_interp(elf_static, sizeof(elf_static), out, sizeof(out));
    ASSERT_EQ(len, 0);
}

static void test_elf_too_short(void)
{
    unsigned char buf[32] = {0x7f, 'E', 'L', 'F'};
    char out[256];
    int len = kbox_parse_elf_interp(buf, sizeof(buf), out, sizeof(out));
    ASSERT_EQ(len, -1);
}

static void test_elf_bad_magic(void)
{
    unsigned char buf[64] = {0};
    char out[256];
    int len = kbox_parse_elf_interp(buf, sizeof(buf), out, sizeof(out));
    ASSERT_EQ(len, -1);
}

static void test_elf_32bit_rejected(void)
{
    unsigned char buf[64] = {0x7f, 'E', 'L', 'F', 1 /* 32-bit */, 1};
    char out[256];
    int len = kbox_parse_elf_interp(buf, sizeof(buf), out, sizeof(out));
    ASSERT_EQ(len, -1);
}

static void test_elf_find_interp_loc(void)
{
    char out[256];
    uint64_t offset = 0, filesz = 0;
    int len = kbox_find_elf_interp_loc(elf_with_interp, sizeof(elf_with_interp),
                                       out, sizeof(out), &offset, &filesz);
    ASSERT_TRUE(len > 0);
    ASSERT_STREQ(out, "/lib64/ld-linux-x86-64.so.2");
    ASSERT_EQ(offset, 120);
    ASSERT_EQ(filesz, 28);
}

static void test_elf_find_interp_loc_static(void)
{
    char out[256];
    uint64_t offset = 0, filesz = 0;
    int len = kbox_find_elf_interp_loc(elf_static, sizeof(elf_static), out,
                                       sizeof(out), &offset, &filesz);
    ASSERT_EQ(len, 0);
    /* offset/filesz should be unchanged (not written for static) */
    ASSERT_EQ(offset, 0);
    ASSERT_EQ(filesz, 0);
}

void test_elf_init(void)
{
    TEST_REGISTER(test_elf_parse_interp);
    TEST_REGISTER(test_elf_static_no_interp);
    TEST_REGISTER(test_elf_too_short);
    TEST_REGISTER(test_elf_bad_magic);
    TEST_REGISTER(test_elf_32bit_rejected);
    TEST_REGISTER(test_elf_find_interp_loc);
    TEST_REGISTER(test_elf_find_interp_loc_static);
}
