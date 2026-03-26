/* SPDX-License-Identifier: MIT */
#ifndef KBOX_LOADER_STACK_H
#define KBOX_LOADER_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "kbox/elf.h"

#define KBOX_LOADER_RANDOM_SIZE 16

struct kbox_loader_auxv_entry {
    uint64_t key;
    uint64_t value;
};

struct kbox_loader_stack_spec {
    const char *const *argv;
    size_t argc;
    const char *const *envp;
    size_t envc;
    const char *execfn;
    const unsigned char *random_bytes;
    const struct kbox_loader_auxv_entry *extra_auxv;
    size_t extra_auxv_count;
    const struct kbox_elf_load_plan *main_plan;
    const struct kbox_elf_load_plan *interp_plan;
    uint64_t main_load_bias;
    uint64_t interp_load_bias;
    uint64_t page_size;
    uint64_t stack_top;
    uint64_t stack_size;
    uint32_t uid;
    uint32_t euid;
    uint32_t gid;
    uint32_t egid;
    int secure;
};

struct kbox_loader_stack_image {
    unsigned char *data;
    size_t size;
    size_t capacity;
    uint64_t initial_sp;
    uint64_t random_addr;
    uint64_t execfn_addr;
};

void kbox_loader_stack_image_reset(struct kbox_loader_stack_image *image);
int kbox_loader_build_initial_stack(const struct kbox_loader_stack_spec *spec,
                                    struct kbox_loader_stack_image *image);

#endif /* KBOX_LOADER_STACK_H */
