/* SPDX-License-Identifier: MIT */
#ifndef KBOX_LOADER_HANDOFF_H
#define KBOX_LOADER_HANDOFF_H

#include <stddef.h>
#include <stdint.h>

#include "loader-entry.h"
#include "loader-image.h"

struct kbox_loader_handoff {
    struct kbox_loader_entry_state entry;
    uint64_t entry_map_start;
    uint64_t entry_map_end;
    uint64_t stack_map_start;
    uint64_t stack_map_end;
    size_t entry_mapping_index;
    size_t stack_mapping_index;
};

int kbox_loader_build_handoff(const struct kbox_loader_layout *layout,
                              const struct kbox_loader_image *image,
                              struct kbox_loader_handoff *handoff);

#endif /* KBOX_LOADER_HANDOFF_H */
