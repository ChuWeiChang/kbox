/* SPDX-License-Identifier: MIT */
#ifndef KBOX_MOUNT_H
#define KBOX_MOUNT_H

struct kbox_sysnrs; /* forward declaration */

/* Mount profile application.
 *
 * Sets up recommended filesystems (proc, sysfs, devtmpfs, tmpfs) and applies
 * user-specified bind mounts.
 */

enum kbox_mount_profile {
    KBOX_MOUNT_FULL,    /* proc, sysfs, devtmpfs, devpts, tmpfs */
    KBOX_MOUNT_MINIMAL, /* proc, tmpfs only */
};

struct kbox_bind_spec {
    char source[4096];
    char target[4096];
};

/* Parse a bind mount specification "SRC:DST".
 * Returns 0 on success, -1 on parse error.
 */
int kbox_parse_bind_spec(const char *spec, struct kbox_bind_spec *out);

/* Apply mounts according to the given profile.
 *   KBOX_MOUNT_FULL:    proc, sysfs, devtmpfs, devpts, tmpfs
 *   KBOX_MOUNT_MINIMAL: proc, tmpfs only
 * Assumes we are already chroot'd.
 * Returns 0 on success, -1 on error.
 */
int kbox_apply_recommended_mounts(const struct kbox_sysnrs *s,
                                  enum kbox_mount_profile profile);

/* Apply bind mounts.
 * Returns 0 on success, -1 on error.
 */
int kbox_apply_bind_mounts(const struct kbox_sysnrs *s,
                           const struct kbox_bind_spec *specs,
                           int count);

#endif /* KBOX_MOUNT_H */
