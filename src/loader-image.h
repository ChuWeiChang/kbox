/* SPDX-License-Identifier: MIT */
#ifndef KBOX_LOADER_IMAGE_H
#define KBOX_LOADER_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#include "loader-layout.h"

struct kbox_loader_image_region {
    void *addr;
    size_t size;
};

struct kbox_loader_image {
    struct kbox_loader_image_region regions[KBOX_LOADER_MAX_MAPPINGS];
    size_t region_count;
};

struct kbox_loader_image_spec {
    const struct kbox_loader_layout *layout;
    const unsigned char *main_elf;
    size_t main_elf_len;
    const unsigned char *interp_elf;
    size_t interp_elf_len;
};

void kbox_loader_image_reset(struct kbox_loader_image *image);
int kbox_loader_materialize_image(const struct kbox_loader_image_spec *spec,
                                  struct kbox_loader_image *image);

#endif /* KBOX_LOADER_IMAGE_H */
