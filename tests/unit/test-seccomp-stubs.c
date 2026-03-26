/* SPDX-License-Identifier: MIT */

#include <errno.h>

#include "seccomp.h"

struct kbox_dispatch kbox_dispatch_errno(int err)
{
    if (err <= 0)
        err = EIO;
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_RETURN,
        .val = 0,
        .error = err,
    };
}

struct kbox_dispatch kbox_dispatch_value(int64_t val)
{
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_RETURN,
        .val = val,
        .error = 0,
    };
}

struct kbox_dispatch kbox_dispatch_request(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req)
{
    struct kbox_dispatch dispatch;

    (void) ctx;
    dispatch.kind = KBOX_DISPATCH_RETURN;
    dispatch.val = req ? req->nr : -1;
    dispatch.error = 0;
    return dispatch;
}
