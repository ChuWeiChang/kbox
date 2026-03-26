/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "loader-stack.h"
#include "test-runner.h"

#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_ENTRY 9
#define AT_RANDOM 25
#define AT_EXECFN 31

static uint64_t read_u64(const unsigned char *p)
{
    uint64_t value;

    memcpy(&value, p, sizeof(value));
    return value;
}

static const unsigned char *stack_ptr(
    const struct kbox_loader_stack_image *image,
    uint64_t addr)
{
    if (addr < image->initial_sp || addr >= image->initial_sp + image->size)
        return NULL;
    return image->data + (addr - image->initial_sp);
}

static uint64_t find_auxv_value(const struct kbox_loader_stack_image *image,
                                size_t argc,
                                size_t envc,
                                uint64_t key)
{
    size_t word = 1 + argc + 1 + envc + 1;
    const unsigned char *p = image->data + word * sizeof(uint64_t);

    for (;;) {
        uint64_t a_type = read_u64(p);
        uint64_t a_val = read_u64(p + sizeof(uint64_t));

        if (a_type == AT_NULL)
            return UINT64_MAX;
        if (a_type == key)
            return a_val;
        p += 2 * sizeof(uint64_t);
    }
}

static void test_loader_build_initial_stack_static(void)
{
    static const char *const argv[] = {"/bin/test", "arg1"};
    static const char *const envp[] = {"A=B", "C=D"};
    static const unsigned char random_bytes[KBOX_LOADER_RANDOM_SIZE] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    };
    struct kbox_elf_load_plan main_plan;
    struct kbox_loader_stack_spec spec;
    struct kbox_loader_stack_image image;
    uint64_t argc_word;
    uint64_t argv0_addr;
    uint64_t argv1_addr;
    uint64_t env0_addr;
    uint64_t at_random;
    uint64_t at_execfn;

    memset(&main_plan, 0, sizeof(main_plan));
    memset(&spec, 0, sizeof(spec));
    memset(&image, 0, sizeof(image));

    main_plan.entry = 0x401020;
    main_plan.phdr_vaddr = 0x400040;
    main_plan.phentsize = 56;
    main_plan.phnum = 3;

    spec.argv = argv;
    spec.argc = 2;
    spec.envp = envp;
    spec.envc = 2;
    spec.execfn = "/guest/bin/test";
    spec.random_bytes = random_bytes;
    spec.main_plan = &main_plan;
    spec.page_size = 4096;
    spec.stack_top = 0x700000010000ULL;
    spec.stack_size = 0x4000;
    spec.uid = 1000;
    spec.euid = 1001;
    spec.gid = 1002;
    spec.egid = 1003;

    ASSERT_EQ(kbox_loader_build_initial_stack(&spec, &image), 0);
    ASSERT_EQ(image.initial_sp & 15, 0);

    argc_word = read_u64(image.data);
    argv0_addr = read_u64(image.data + 8);
    argv1_addr = read_u64(image.data + 16);
    env0_addr = read_u64(image.data + 32);

    ASSERT_EQ(argc_word, 2);
    ASSERT_STREQ((const char *) stack_ptr(&image, argv0_addr), "/bin/test");
    ASSERT_STREQ((const char *) stack_ptr(&image, argv1_addr), "arg1");
    ASSERT_STREQ((const char *) stack_ptr(&image, env0_addr), "A=B");

    ASSERT_EQ(find_auxv_value(&image, spec.argc, spec.envc, AT_PHDR), 0x400040);
    ASSERT_EQ(find_auxv_value(&image, spec.argc, spec.envc, AT_PHENT), 56);
    ASSERT_EQ(find_auxv_value(&image, spec.argc, spec.envc, AT_PHNUM), 3);
    ASSERT_EQ(find_auxv_value(&image, spec.argc, spec.envc, AT_PAGESZ), 4096);
    ASSERT_EQ(find_auxv_value(&image, spec.argc, spec.envc, AT_ENTRY),
              0x401020);

    at_random = find_auxv_value(&image, spec.argc, spec.envc, AT_RANDOM);
    at_execfn = find_auxv_value(&image, spec.argc, spec.envc, AT_EXECFN);
    ASSERT_TRUE(stack_ptr(&image, at_random) != NULL);
    ASSERT_TRUE(stack_ptr(&image, at_execfn) != NULL);
    ASSERT_EQ(memcmp(stack_ptr(&image, at_random), random_bytes,
                     KBOX_LOADER_RANDOM_SIZE),
              0);
    ASSERT_STREQ((const char *) stack_ptr(&image, at_execfn),
                 "/guest/bin/test");

    kbox_loader_stack_image_reset(&image);
}

static void test_loader_build_initial_stack_dynamic_interp(void)
{
    static const char *const argv[] = {"/lib/ld-musl-aarch64.so.1", "sh"};
    struct kbox_elf_load_plan main_plan;
    struct kbox_elf_load_plan interp_plan;
    struct kbox_loader_stack_spec spec;
    struct kbox_loader_stack_image image;

    memset(&main_plan, 0, sizeof(main_plan));
    memset(&interp_plan, 0, sizeof(interp_plan));
    memset(&spec, 0, sizeof(spec));
    memset(&image, 0, sizeof(image));

    main_plan.entry = 0x1230;
    main_plan.phdr_vaddr = 0x40;
    main_plan.phentsize = 56;
    main_plan.phnum = 5;
    interp_plan.entry = 0x890;

    spec.argv = argv;
    spec.argc = 2;
    spec.main_plan = &main_plan;
    spec.interp_plan = &interp_plan;
    spec.main_load_bias = 0x555500000000ULL;
    spec.interp_load_bias = 0x777700000000ULL;
    spec.page_size = 4096;
    spec.stack_top = 0x7fff00002000ULL;
    spec.stack_size = 0x4000;

    ASSERT_EQ(kbox_loader_build_initial_stack(&spec, &image), 0);
    ASSERT_EQ(find_auxv_value(&image, spec.argc, spec.envc, AT_PHDR),
              spec.main_load_bias + 0x40);
    ASSERT_EQ(find_auxv_value(&image, spec.argc, spec.envc, AT_ENTRY),
              spec.main_load_bias + 0x1230);
    ASSERT_EQ(find_auxv_value(&image, spec.argc, spec.envc, AT_BASE),
              spec.interp_load_bias);

    kbox_loader_stack_image_reset(&image);
}

static void test_loader_build_initial_stack_rejects_small_stack(void)
{
    static const char *const argv[] = {"/bin/test"};
    struct kbox_elf_load_plan main_plan;
    struct kbox_loader_stack_spec spec;
    struct kbox_loader_stack_image image;

    memset(&main_plan, 0, sizeof(main_plan));
    memset(&spec, 0, sizeof(spec));
    memset(&image, 0, sizeof(image));

    main_plan.entry = 0x1000;
    main_plan.phdr_vaddr = 0x40;
    main_plan.phentsize = 56;
    main_plan.phnum = 2;

    spec.argv = argv;
    spec.argc = 1;
    spec.main_plan = &main_plan;
    spec.page_size = 4096;
    spec.stack_top = 0x1000;
    spec.stack_size = 32;

    ASSERT_EQ(kbox_loader_build_initial_stack(&spec, &image), -1);
}

void test_loader_stack_init(void)
{
    TEST_REGISTER(test_loader_build_initial_stack_static);
    TEST_REGISTER(test_loader_build_initial_stack_dynamic_interp);
    TEST_REGISTER(test_loader_build_initial_stack_rejects_small_stack);
}
