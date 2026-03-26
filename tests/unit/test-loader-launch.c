/* SPDX-License-Identifier: MIT */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "loader-launch.h"
#include "test-runner.h"

#define ET_EXEC 2
#define ET_DYN 3
#define PT_INTERP 3
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
                       uint16_t type,
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
    set_le16(buf + 16, type);
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
    init_elf64(elf, elf_size, ET_DYN, machine, 0x80, 2);
    set_phdr(elf, 0, PT_LOAD, PF_R | PF_X, 0, 0, 0x200, 0x200, 0x1000);
    set_phdr(elf, 1, PT_INTERP, PF_R, 0x200, 0, 0x20, 0x20, 1);
}

static void build_interp_pie(unsigned char *elf,
                             size_t elf_size,
                             uint16_t machine)
{
    init_elf64(elf, elf_size, ET_DYN, machine, 0x140, 1);
    set_phdr(elf, 0, PT_LOAD, PF_R | PF_X, 0, 0, 0x200, 0x200, 0x1000);
}

static int create_memfd_with_bytes(const unsigned char *buf, size_t len)
{
    int fd = memfd_create("kbox-loader-launch-test", MFD_CLOEXEC);

    if (fd < 0)
        return -1;
    if (write(fd, buf, len) != (ssize_t) len) {
        close(fd);
        return -1;
    }
    return fd;
}

static void test_loader_prepare_launch_main_only_pie(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char elf[2048];
    struct kbox_loader_launch launch;
    struct kbox_loader_launch_spec spec;
    int fd;

    build_main_pie(elf, sizeof(elf), 0x3e);
    fd = create_memfd_with_bytes(elf, sizeof(elf));
    ASSERT_NE(fd, -1);

    memset(&launch, 0, sizeof(launch));
    memset(&spec, 0, sizeof(spec));
    spec.exec_fd = fd;
    spec.interp_fd = -1;
    spec.argv = argv;
    spec.argc = 1;
    spec.page_size = 4096;
    spec.main_load_bias = 0x600700000000ULL;
    spec.stack_top = 0x700700010000ULL;

    ASSERT_EQ(kbox_loader_prepare_launch(&spec, &launch), 0);
    ASSERT_EQ(launch.transfer.arch, KBOX_LOADER_ENTRY_ARCH_X86_64);
    ASSERT_EQ(launch.layout.main_load_bias, 0x600700000000ULL);
    ASSERT_EQ(launch.transfer.pc, launch.layout.initial_pc);
    ASSERT_EQ(launch.transfer.pc, 0x600700000080ULL);
    ASSERT_EQ(launch.transfer.sp, launch.layout.initial_sp);
    ASSERT_EQ(launch.image.region_count, launch.layout.mapping_count);

    kbox_loader_launch_reset(&launch);
    close(fd);
}

static void test_loader_prepare_launch_dynamic_interp(void)
{
    static const char *const argv[] = {"/lib/ld-musl-aarch64.so.1", "sh"};
    unsigned char main_elf[2048];
    unsigned char interp_elf[2048];
    struct kbox_loader_launch launch;
    struct kbox_loader_launch_spec spec;
    int exec_fd;
    int interp_fd;

    build_main_pie(main_elf, sizeof(main_elf), 0xb7);
    build_interp_pie(interp_elf, sizeof(interp_elf), 0xb7);
    memcpy(main_elf + 0x200, "/lib/ld-musl-aarch64.so.1", 26);
    exec_fd = create_memfd_with_bytes(main_elf, sizeof(main_elf));
    interp_fd = create_memfd_with_bytes(interp_elf, sizeof(interp_elf));
    ASSERT_NE(exec_fd, -1);
    ASSERT_NE(interp_fd, -1);

    memset(&launch, 0, sizeof(launch));
    memset(&spec, 0, sizeof(spec));
    spec.exec_fd = exec_fd;
    spec.interp_fd = interp_fd;
    spec.argv = argv;
    spec.argc = 2;
    spec.page_size = 4096;
    spec.main_load_bias = 0x600800000000ULL;
    spec.interp_load_bias = 0x600810000000ULL;
    spec.stack_top = 0x700800010000ULL;

    ASSERT_EQ(kbox_loader_prepare_launch(&spec, &launch), 0);
    ASSERT_EQ(launch.layout.has_interp, 1);
    ASSERT_EQ(launch.transfer.arch, KBOX_LOADER_ENTRY_ARCH_AARCH64);
    ASSERT_EQ(launch.transfer.pc, launch.layout.initial_pc);
    ASSERT_EQ(launch.transfer.entry_map_start, launch.handoff.entry_map_start);

    kbox_loader_launch_reset(&launch);
    close(interp_fd);
    close(exec_fd);
}

static void test_loader_prepare_launch_rejects_empty_fd(void)
{
    static const char *const argv[] = {"/bin/test"};
    struct kbox_loader_launch launch;
    struct kbox_loader_launch_spec spec;
    int fd = memfd_create("kbox-loader-empty", MFD_CLOEXEC);

    ASSERT_NE(fd, -1);
    memset(&launch, 0, sizeof(launch));
    memset(&spec, 0, sizeof(spec));
    spec.exec_fd = fd;
    spec.interp_fd = -1;
    spec.argv = argv;
    spec.argc = 1;
    spec.page_size = 4096;
    spec.stack_top = 0x700900010000ULL;

    ASSERT_EQ(kbox_loader_prepare_launch(&spec, &launch), -1);

    kbox_loader_launch_reset(&launch);
    close(fd);
}

static void test_loader_collect_exec_ranges_static_exec(void)
{
    static const char *const argv[] = {"/bin/test"};
    unsigned char elf[2048];
    struct kbox_loader_launch launch;
    struct kbox_loader_launch_spec spec;
    struct kbox_loader_exec_range ranges[4];
    size_t range_count = 0;
    int fd;

    build_main_pie(elf, sizeof(elf), 0x3e);
    fd = create_memfd_with_bytes(elf, sizeof(elf));
    ASSERT_NE(fd, -1);

    memset(&launch, 0, sizeof(launch));
    memset(&spec, 0, sizeof(spec));
    spec.exec_fd = fd;
    spec.interp_fd = -1;
    spec.argv = argv;
    spec.argc = 1;
    spec.page_size = 4096;
    spec.main_load_bias = 0x600700000000ULL;
    spec.stack_top = 0x700700010000ULL;

    ASSERT_EQ(kbox_loader_prepare_launch(&spec, &launch), 0);
    ASSERT_EQ(kbox_loader_collect_exec_ranges(&launch, ranges, 4, &range_count),
              0);
    ASSERT_EQ(range_count, 1);
    ASSERT_EQ(ranges[0].start, launch.layout.mappings[0].addr);
    ASSERT_EQ(ranges[0].end,
              launch.layout.mappings[0].addr + launch.layout.mappings[0].size);

    kbox_loader_launch_reset(&launch);
    close(fd);
}

static void test_loader_collect_exec_ranges_dynamic_interp(void)
{
    static const char *const argv[] = {"/lib/ld-musl-aarch64.so.1", "sh"};
    unsigned char main_elf[2048];
    unsigned char interp_elf[2048];
    struct kbox_loader_launch launch;
    struct kbox_loader_launch_spec spec;
    struct kbox_loader_exec_range ranges[4];
    size_t range_count = 0;
    int exec_fd;
    int interp_fd;

    build_main_pie(main_elf, sizeof(main_elf), 0xb7);
    build_interp_pie(interp_elf, sizeof(interp_elf), 0xb7);
    memcpy(main_elf + 0x200, "/lib/ld-musl-aarch64.so.1", 26);
    exec_fd = create_memfd_with_bytes(main_elf, sizeof(main_elf));
    interp_fd = create_memfd_with_bytes(interp_elf, sizeof(interp_elf));
    ASSERT_NE(exec_fd, -1);
    ASSERT_NE(interp_fd, -1);

    memset(&launch, 0, sizeof(launch));
    memset(&spec, 0, sizeof(spec));
    spec.exec_fd = exec_fd;
    spec.interp_fd = interp_fd;
    spec.argv = argv;
    spec.argc = 2;
    spec.page_size = 4096;
    spec.main_load_bias = 0x600800000000ULL;
    spec.interp_load_bias = 0x600810000000ULL;
    spec.stack_top = 0x700800010000ULL;

    ASSERT_EQ(kbox_loader_prepare_launch(&spec, &launch), 0);
    ASSERT_EQ(kbox_loader_collect_exec_ranges(&launch, ranges, 4, &range_count),
              0);
    ASSERT_EQ(range_count, 2);

    kbox_loader_launch_reset(&launch);
    close(interp_fd);
    close(exec_fd);
}

void test_loader_launch_init(void)
{
    TEST_REGISTER(test_loader_prepare_launch_main_only_pie);
    TEST_REGISTER(test_loader_prepare_launch_dynamic_interp);
    TEST_REGISTER(test_loader_prepare_launch_rejects_empty_fd);
    TEST_REGISTER(test_loader_collect_exec_ranges_static_exec);
    TEST_REGISTER(test_loader_collect_exec_ranges_dynamic_interp);
}
