/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SECCOMP_H
#define KBOX_SECCOMP_H

#include <stdint.h>
#include <sys/types.h>

#include "fd-table.h"
#include "seccomp-defs.h"
#include "syscall-nr.h"

struct kbox_dispatch {
    enum {
        KBOX_DISPATCH_CONTINUE,
        KBOX_DISPATCH_RETURN,
    } kind;
    int64_t val;
    int error;
};

struct kbox_web_ctx;

struct kbox_supervisor_ctx {
    const struct kbox_sysnrs *sysnrs;
    const struct kbox_host_nrs *host_nrs;
    struct kbox_fd_table *fd_table;
    int listener_fd;
    pid_t child_pid;
    const char *host_root;
    int verbose;
    int root_identity;
    uid_t override_uid;
    gid_t override_gid;
    int normalize;
    struct kbox_web_ctx *web;
};

int kbox_install_seccomp_listener(const struct kbox_host_nrs *h);
int kbox_notify_recv(int listener_fd, void *notif);
int kbox_notify_send(int listener_fd, const void *resp);
int kbox_notify_addfd(int listener_fd,
                      uint64_t id,
                      int srcfd,
                      uint32_t newfd_flags);
int kbox_notify_addfd_at(int listener_fd,
                         uint64_t id,
                         int srcfd,
                         int target_fd,
                         uint32_t newfd_flags);
struct kbox_dispatch kbox_dispatch_syscall(struct kbox_supervisor_ctx *ctx,
                                           const void *notif);
struct kbox_dispatch kbox_dispatch_continue(void);
struct kbox_dispatch kbox_dispatch_errno(int err);
struct kbox_dispatch kbox_dispatch_value(int64_t val);
struct kbox_dispatch kbox_dispatch_from_lkl(long ret);
int kbox_run_supervisor(const struct kbox_sysnrs *sysnrs,
                        const char *command,
                        const char *const *args,
                        int nargs,
                        const char *host_root,
                        int exec_memfd,
                        int verbose,
                        int root_identity,
                        int normalize,
                        struct kbox_web_ctx *web);

#define KBOX_IO_CHUNK_LEN (128 * 1024)

#endif /* KBOX_SECCOMP_H */
