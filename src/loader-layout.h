/* SPDX-License-Identifier: MIT */
#ifndef KBOX_LOADER_LAYOUT_H
#define KBOX_LOADER_LAYOUT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

#include "loader-stack.h"

#define KBOX_LOADER_DEFAULT_STACK_SIZE (8u * 1024u * 1024u)
#define KBOX_LOADER_MAX_MAPPINGS (3 * KBOX_ELF_MAX_LOAD_SEGMENTS + 1)

enum kbox_loader_mapping_source {
    KBOX_LOADER_MAPPING_MAIN,
    KBOX_LOADER_MAPPING_INTERP,
    KBOX_LOADER_MAPPING_STACK,
};

struct kbox_loader_mapping {
    uint64_t addr;
    uint64_t size;
    uint64_t file_offset;
    uint64_t file_size;
    uint64_t zero_fill_start;
    uint64_t zero_fill_size;
    int prot;
    int flags;
    enum kbox_loader_mapping_source source;
};

struct kbox_loader_layout {
    struct kbox_elf_load_plan main_plan;
    struct kbox_elf_load_plan interp_plan;
    struct kbox_loader_stack_image stack;
    struct kbox_loader_mapping mappings[KBOX_LOADER_MAX_MAPPINGS];
    uint64_t main_load_bias;
    uint64_t interp_load_bias;
    uint64_t initial_pc;
    uint64_t initial_sp;
    uint64_t stack_top;
    uint64_t stack_size;
    size_t mapping_count;
    int has_interp;
};

struct kbox_loader_layout_spec {
    const unsigned char *main_elf;
    size_t main_elf_len;
    const unsigned char *interp_elf;
    size_t interp_elf_len;
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

void kbox_loader_layout_reset(struct kbox_loader_layout *layout);
int kbox_loader_build_layout(const struct kbox_loader_layout_spec *spec,
                             struct kbox_loader_layout *layout);

#endif /* KBOX_LOADER_LAYOUT_H */
