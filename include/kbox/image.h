/* SPDX-License-Identifier: MIT */

#ifndef KBOX_IMAGE_H
#define KBOX_IMAGE_H

#include "kbox/cli.h"

/* Image mode lifecycle.
 *
 * 1. Open the image file
 * 2. Register it as an LKL block device
 * 3. Boot the LKL kernel
 * 4. Mount the filesystem
 * 5. Chroot into the mount point
 * 6. Apply recommended mounts / bind mounts
 * 7. Set working directory and identity
 * 8. Fork child, install seccomp, exec command
 * 9. Run the supervisor loop
 */

/* Run image mode with the given arguments.
 * Returns 0 on success, -1 on error (message printed to stderr).
 */
int kbox_run_image(const struct kbox_image_args *args);

#endif /* KBOX_IMAGE_H */
