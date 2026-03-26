/* SPDX-License-Identifier: MIT */
#ifndef KBOX_LOADER_LAUNCH_H
#define KBOX_LOADER_LAUNCH_H

#include <stddef.h>
#include <stdint.h>

#include "loader-handoff.h"
#include "loader-image.h"
#include "loader-layout.h"
#include "loader-transfer.h"

struct kbox_loader_exec_range {
    uint64_t start;
    uint64_t end;
};

struct kbox_loader_launch {
    unsigned char *main_elf;
    size_t main_elf_len;
    unsigned char *interp_elf;
    size_t interp_elf_len;
    struct kbox_loader_layout layout;
    struct kbox_loader_image image;
    struct kbox_loader_handoff handoff;
    struct kbox_loader_transfer_state transfer;
};

struct kbox_loader_launch_spec {
    int exec_fd;
    int interp_fd;
    const char *const *argv;
    size_t argc;
    const char *const *envp;
    size_t envc;
    const char *execfn;
    const unsigned char *random_bytes;
    const struct kbox_loader_auxv_entry *extra_auxv;
    size_t extra_auxv_count;
    uint64_t page_size;
    uint64_t stack_top;
    uint64_t stack_size;
    uint64_t main_load_bias;
    uint64_t interp_load_bias;
    uint32_t uid;
    uint32_t euid;
    uint32_t gid;
    uint32_t egid;
    int secure;
};

void kbox_loader_launch_reset(struct kbox_loader_launch *launch);
int kbox_loader_prepare_launch(const struct kbox_loader_launch_spec *spec,
                               struct kbox_loader_launch *launch);
int kbox_loader_collect_exec_ranges(const struct kbox_loader_launch *launch,
                                    struct kbox_loader_exec_range *ranges,
                                    size_t range_cap,
                                    size_t *range_count);

#endif /* KBOX_LOADER_LAUNCH_H */
