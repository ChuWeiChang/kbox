/* SPDX-License-Identifier: MIT */

#ifndef KBOX_IDENTITY_H
#define KBOX_IDENTITY_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct kbox_sysnrs; /* forward declaration */

/* Identity management and permission normalization.
 *
 * kbox can fake identity (uid/gid) inside the guest and normalize displayed
 * permissions to match realistic Linux defaults.
 */

/* Normalized permission entry for well-known paths.
 * Returns true if path has a normalized permission, filling out mode/uid/gid.
 */
bool kbox_normalized_permissions(const char *path,
                                 uint32_t *mode,
                                 uint32_t *uid,
                                 uint32_t *gid);

/* Simple hash of a username for generating consistent UIDs.
 * Used by normalized_permissions for /home/<user>.
 */
uint32_t kbox_hash_username(const char *name);

/* Parse a "UID:GID" identity specification.
 * Returns 0 on success, -1 on parse error.
 */
int kbox_parse_change_id(const char *spec, uid_t *uid, gid_t *gid);

/* Apply guest identity inside LKL.
 * If root_id is true, sets uid=0 gid=0.
 * If override_uid/gid >= 0, uses those.
 * Otherwise passthrough (no change).
 */
int kbox_apply_guest_identity(const struct kbox_sysnrs *s,
                              bool root_id,
                              uid_t override_uid,
                              gid_t override_gid);

#endif /* KBOX_IDENTITY_H */
