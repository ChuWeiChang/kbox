/* SPDX-License-Identifier: MIT */

#include <string.h>

#include "seccomp.h"
#include "test-runner.h"

static const struct kbox_guest_mem_ops custom_guest_mem_ops = {
    .read = NULL,
    .write = NULL,
    .write_force = NULL,
    .read_string = NULL,
    .read_open_how = NULL,
};

static void test_request_init_from_regs_seccomp_defaults_process_vm(void)
{
    struct kbox_syscall_request req;
    struct kbox_syscall_regs regs = {
        .nr = 39,
        .instruction_pointer = 0x401000,
        .args = {1, 2, 3, 4, 5, 6},
    };

    ASSERT_EQ(kbox_syscall_request_init_from_regs(
                  &req, KBOX_SYSCALL_SOURCE_SECCOMP, 1234, 0x55, &regs, NULL),
              0);
    ASSERT_EQ(req.source, KBOX_SYSCALL_SOURCE_SECCOMP);
    ASSERT_EQ(req.pid, 1234);
    ASSERT_EQ(req.cookie, 0x55);
    ASSERT_EQ(req.nr, 39);
    ASSERT_EQ(req.instruction_pointer, 0x401000);
    ASSERT_EQ(req.args[0], 1);
    ASSERT_EQ(req.args[5], 6);
    ASSERT_EQ(req.guest_mem.ops, &kbox_process_vm_guest_mem_ops);
    ASSERT_EQ(req.guest_mem.opaque, (uintptr_t) 1234);
}

static void test_request_init_from_regs_preserves_custom_guest_mem(void)
{
    struct kbox_syscall_request req;
    struct kbox_syscall_regs regs = {
        .nr = 172,
        .instruction_pointer = 0x8040,
        .args = {7, 8, 9, 10, 11, 12},
    };
    struct kbox_guest_mem guest_mem = {
        .ops = &custom_guest_mem_ops,
        .opaque = 0xdeadbeef,
    };

    ASSERT_EQ(kbox_syscall_request_init_from_regs(
                  &req, KBOX_SYSCALL_SOURCE_TRAP, 77, 0, &regs, &guest_mem),
              0);
    ASSERT_EQ(req.source, KBOX_SYSCALL_SOURCE_TRAP);
    ASSERT_EQ(req.pid, 77);
    ASSERT_EQ(req.nr, 172);
    ASSERT_EQ(req.instruction_pointer, 0x8040);
    ASSERT_EQ(req.args[1], 8);
    ASSERT_EQ(req.guest_mem.ops, &custom_guest_mem_ops);
    ASSERT_EQ(req.guest_mem.opaque, (uintptr_t) 0xdeadbeef);
}

static void test_request_from_notif_uses_shared_decoder(void)
{
    struct kbox_seccomp_notif notif;
    struct kbox_syscall_request req;

    memset(&notif, 0, sizeof(notif));
    notif.id = 0x1234;
    notif.pid = 4321;
    notif.data.nr = 59;
    notif.data.instruction_pointer = 0xfeedface;
    notif.data.args[0] = 11;
    notif.data.args[5] = 66;

    ASSERT_EQ(kbox_syscall_request_from_notif(&notif, &req), 0);
    ASSERT_EQ(req.source, KBOX_SYSCALL_SOURCE_SECCOMP);
    ASSERT_EQ(req.pid, 4321);
    ASSERT_EQ(req.cookie, 0x1234);
    ASSERT_EQ(req.nr, 59);
    ASSERT_EQ(req.instruction_pointer, 0xfeedface);
    ASSERT_EQ(req.args[0], 11);
    ASSERT_EQ(req.args[5], 66);
    ASSERT_EQ(req.guest_mem.ops, &kbox_process_vm_guest_mem_ops);
    ASSERT_EQ(req.guest_mem.opaque, (uintptr_t) 4321);
}

void test_syscall_request_init(void)
{
    TEST_REGISTER(test_request_init_from_regs_seccomp_defaults_process_vm);
    TEST_REGISTER(test_request_init_from_regs_preserves_custom_guest_mem);
    TEST_REGISTER(test_request_from_notif_uses_shared_decoder);
}
