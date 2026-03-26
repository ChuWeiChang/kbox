/* SPDX-License-Identifier: MIT */

#include <string.h>

#include "loader-handoff.h"

static int region_matches_mapping(const struct kbox_loader_image *image,
                                  const struct kbox_loader_mapping *mapping,
                                  size_t index)
{
    const struct kbox_loader_image_region *region;

    if (!image || !mapping || index >= image->region_count)
        return 0;
    region = &image->regions[index];
    return region->addr == (void *) (uintptr_t) mapping->addr &&
           region->size == (size_t) mapping->size;
}

static int find_entry_mapping(const struct kbox_loader_layout *layout,
                              uint64_t pc,
                              size_t *index_out)
{
    for (size_t i = 0; i < layout->mapping_count; i++) {
        const struct kbox_loader_mapping *mapping = &layout->mappings[i];
        uint64_t end;

        if ((mapping->prot & PROT_EXEC) == 0 || mapping->size == 0)
            continue;
        if (__builtin_add_overflow(mapping->addr, mapping->size, &end))
            return -1;
        if (pc >= mapping->addr && pc < end) {
            if (index_out)
                *index_out = i;
            return 0;
        }
    }
    return -1;
}

static int find_stack_mapping(const struct kbox_loader_layout *layout,
                              uint64_t sp,
                              size_t *index_out)
{
    for (size_t i = 0; i < layout->mapping_count; i++) {
        const struct kbox_loader_mapping *mapping = &layout->mappings[i];
        uint64_t end;

        if (mapping->source != KBOX_LOADER_MAPPING_STACK || mapping->size == 0)
            continue;
        if (__builtin_add_overflow(mapping->addr, mapping->size, &end))
            return -1;
        if (sp >= mapping->addr && sp < end) {
            if (index_out)
                *index_out = i;
            return 0;
        }
    }
    return -1;
}

int kbox_loader_build_handoff(const struct kbox_loader_layout *layout,
                              const struct kbox_loader_image *image,
                              struct kbox_loader_handoff *handoff)
{
    struct kbox_loader_entry_state entry;
    size_t entry_index;
    size_t stack_index;
    uint64_t entry_map_end;
    uint64_t stack_map_end;

    if (!layout || !image || !handoff)
        return -1;
    if (layout->mapping_count == 0 ||
        image->region_count < layout->mapping_count)
        return -1;
    if (kbox_loader_build_entry_state(layout, &entry) < 0)
        return -1;
    if ((entry.sp & 0xfu) != 0)
        return -1;
    if (find_entry_mapping(layout, entry.pc, &entry_index) < 0)
        return -1;
    if (find_stack_mapping(layout, entry.sp, &stack_index) < 0)
        return -1;
    if (!region_matches_mapping(image, &layout->mappings[entry_index],
                                entry_index) ||
        !region_matches_mapping(image, &layout->mappings[stack_index],
                                stack_index)) {
        return -1;
    }
    if (__builtin_add_overflow(layout->mappings[entry_index].addr,
                               layout->mappings[entry_index].size,
                               &entry_map_end) ||
        __builtin_add_overflow(layout->mappings[stack_index].addr,
                               layout->mappings[stack_index].size,
                               &stack_map_end)) {
        return -1;
    }

    memset(handoff, 0, sizeof(*handoff));
    handoff->entry = entry;
    handoff->entry_mapping_index = entry_index;
    handoff->stack_mapping_index = stack_index;
    handoff->entry_map_start = layout->mappings[entry_index].addr;
    handoff->entry_map_end = entry_map_end;
    handoff->stack_map_start = layout->mappings[stack_index].addr;
    handoff->stack_map_end = stack_map_end;
    return 0;
}
