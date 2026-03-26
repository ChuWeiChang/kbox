/* SPDX-License-Identifier: MIT */

#include <string.h>

#include "seccomp.h"

int kbox_syscall_request_init_from_regs(struct kbox_syscall_request *out,
                                        enum kbox_syscall_source source,
                                        pid_t pid,
                                        uint64_t cookie,
                                        const struct kbox_syscall_regs *regs,
                                        const struct kbox_guest_mem *guest_mem)
{
    if (!out || !regs)
        return -1;

    memset(out, 0, sizeof(*out));
    out->source = source;
    out->pid = pid;
    out->cookie = cookie;
    out->nr = regs->nr;
    out->instruction_pointer = regs->instruction_pointer;
    memcpy(out->args, regs->args, sizeof(out->args));

    if (guest_mem) {
        out->guest_mem = *guest_mem;
    } else if (source == KBOX_SYSCALL_SOURCE_SECCOMP) {
        out->guest_mem.ops = &kbox_process_vm_guest_mem_ops;
        out->guest_mem.opaque = (uintptr_t) pid;
    }

    return 0;
}

int kbox_syscall_request_from_notif(const void *notif_ptr,
                                    struct kbox_syscall_request *out)
{
    const struct kbox_seccomp_notif *notif = notif_ptr;
    struct kbox_syscall_regs regs;

    if (!notif || !out)
        return -1;

    regs.nr = notif->data.nr;
    regs.instruction_pointer = notif->data.instruction_pointer;
    memcpy(regs.args, notif->data.args, sizeof(regs.args));
    return kbox_syscall_request_init_from_regs(out, KBOX_SYSCALL_SOURCE_SECCOMP,
                                               (pid_t) notif->pid, notif->id,
                                               &regs, NULL);
}
