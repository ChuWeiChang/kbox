/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "kbox/identity.h"
#include "lkl-wrap.h"

/* djb2 hash: deterministic username-to-uid mapping.
 * Produces a 32-bit hash; the caller reduces it modulo the desired range.
 */
uint32_t kbox_hash_username(const char *name)
{
    uint32_t hash = 5381;

    while (*name)
        hash = hash * 33 + (unsigned char) *name++;
    return hash;
}

/* return true if |path| equals |exact| or starts with |prefix/|. */
static bool match_prefix(const char *path, const char *prefix)
{
    size_t len = strlen(prefix);

    if (strncmp(path, prefix, len) != 0)
        return false;
    return path[len] == '\0' || path[len] == '/';
}

/* Extract the basename (last component) from a path.
 * Returns a pointer into |path| itself.
 */
static const char *basename_of(const char *path)
{
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

/* Check if a basename matches any of the well-known setuid binaries. */
static bool is_setuid_binary(const char *base)
{
    static const char *const setuid_bins[] = {
        "passwd", "su",     "sudo", "mount", "umount",  "ping",
        "ping6",  "newgrp", "chfn", "chsh",  "gpasswd",
    };

    for (size_t i = 0; i < sizeof(setuid_bins) / sizeof(setuid_bins[0]); i++) {
        if (strcmp(base, setuid_bins[i]) == 0)
            return true;
    }
    return false;
}

/* Extract the third component from a path like "/home/user".
 * Writes into |buf| (up to |sz| bytes including NUL).
 * Returns false if the path does not have exactly 3 components.
 */
static bool extract_username(const char *path, char *buf, size_t sz)
{
    /* Must start with "/home/" */
    if (strncmp(path, "/home/", 6) != 0)
        return false;

    const char *user = path + 6;
    /* Must not contain another slash and must not be empty */
    if (*user == '\0' || strchr(user, '/') != NULL)
        return false;
    size_t len = strlen(user);
    if (len >= sz)
        return false;
    memcpy(buf, user, len + 1);
    return true;
}

bool kbox_normalized_permissions(const char *path,
                                 uint32_t *mode,
                                 uint32_t *uid,
                                 uint32_t *gid)
{
    if (!path || !mode || !uid || !gid)
        return false;

    /* /tmp: sticky + world-writable */
    if (strcmp(path, "/tmp") == 0) {
        *mode = 01777;
        *uid = 0;
        *gid = 0;
        return true;
    }

    /* /proc, /sys: read-only traversal */
    if (strcmp(path, "/proc") == 0 || strcmp(path, "/sys") == 0) {
        *mode = 0555;
        *uid = 0;
        *gid = 0;
        return true;
    }

    /* /home directory itself */
    if (strcmp(path, "/home") == 0) {
        *mode = 0755;
        *uid = 0;
        *gid = 0;
        return true;
    }

    /* /etc and special files */
    if (strcmp(path, "/etc") == 0) {
        *mode = 0755;
        *uid = 0;
        *gid = 0;
        return true;
    }
    if (strcmp(path, "/etc/passwd") == 0) {
        *mode = 0644;
        *uid = 0;
        *gid = 0;
        return true;
    }
    if (strcmp(path, "/etc/shadow") == 0 || strcmp(path, "/etc/gshadow") == 0) {
        *mode = 0640;
        *uid = 0;
        *gid = 0;
        return true;
    }

    /* /var directory tree */
    if (strcmp(path, "/var") == 0 || strcmp(path, "/var/lib") == 0 ||
        strcmp(path, "/var/cache") == 0 || strcmp(path, "/var/log") == 0 ||
        strcmp(path, "/var/run") == 0 || strcmp(path, "/var/spool") == 0 ||
        strcmp(path, "/var/tmp") == 0 || strcmp(path, "/var/www") == 0 ||
        strcmp(path, "/var/mail") == 0 || match_prefix(path, "/var/lib") ||
        match_prefix(path, "/var/cache") || match_prefix(path, "/var/log") ||
        match_prefix(path, "/var/spool") || match_prefix(path, "/var/www") ||
        match_prefix(path, "/var/mail")) {
        *mode = 0755;
        *uid = 0;
        *gid = 0;
        return true;
    }

    /* /usr directory tree */
    if (strcmp(path, "/usr") == 0 || strcmp(path, "/usr/local") == 0 ||
        strcmp(path, "/usr/lib") == 0 || strcmp(path, "/usr/lib64") == 0 ||
        strcmp(path, "/usr/share") == 0 || strcmp(path, "/usr/include") == 0 ||
        strcmp(path, "/usr/src") == 0 || match_prefix(path, "/usr/lib") ||
        match_prefix(path, "/usr/share") ||
        match_prefix(path, "/usr/include") || match_prefix(path, "/usr/src") ||
        match_prefix(path, "/usr/local")) {
        *mode = 0755;
        *uid = 0;
        *gid = 0;
        return true;
    }

    /* /lib directories */
    if (strcmp(path, "/lib") == 0 || strcmp(path, "/lib64") == 0 ||
        strcmp(path, "/lib32") == 0 || strcmp(path, "/libx32") == 0 ||
        match_prefix(path, "/lib") || match_prefix(path, "/lib64") ||
        match_prefix(path, "/lib32") || match_prefix(path, "/libx32")) {
        *mode = 0755;
        *uid = 0;
        *gid = 0;
        return true;
    }

    /* /etc/apt, /etc/dpkg, /etc/alternatives */
    if (strcmp(path, "/etc/apt") == 0 || strcmp(path, "/etc/dpkg") == 0 ||
        match_prefix(path, "/etc/apt") || match_prefix(path, "/etc/dpkg") ||
        match_prefix(path, "/etc/alternatives")) {
        *mode = 0755;
        *uid = 0;
        *gid = 0;
        return true;
    }

    /* /dev special files */
    if (strcmp(path, "/dev/null") == 0 || strcmp(path, "/dev/zero") == 0 ||
        strcmp(path, "/dev/random") == 0 || strcmp(path, "/dev/urandom") == 0) {
        *mode = 0666;
        *uid = 0;
        *gid = 0;
        return true;
    }
    if (strcmp(path, "/dev/tty") == 0) {
        *mode = 0666;
        *uid = 0;
        *gid = 5;
        return true;
    }
    if (strcmp(path, "/dev/console") == 0) {
        *mode = 0600;
        *uid = 0;
        *gid = 0;
        return true;
    }

    /* Binary directories themselves */
    if (strcmp(path, "/bin") == 0 || strcmp(path, "/usr/bin") == 0 ||
        strcmp(path, "/sbin") == 0 || strcmp(path, "/usr/sbin") == 0 ||
        strcmp(path, "/usr/local/bin") == 0 ||
        strcmp(path, "/usr/local/sbin") == 0) {
        *mode = 0755;
        *uid = 0;
        *gid = 0;
        return true;
    }

    /* Files inside binary directories */
    if (match_prefix(path, "/bin") || match_prefix(path, "/usr/bin") ||
        match_prefix(path, "/sbin") || match_prefix(path, "/usr/sbin") ||
        match_prefix(path, "/usr/local/bin") ||
        match_prefix(path, "/usr/local/sbin")) {
        const char *base = basename_of(path);
        if (is_setuid_binary(base)) {
            *mode = 04755;
            *uid = 0;
            *gid = 0;
        } else {
            *mode = 0755;
            *uid = 0;
            *gid = 0;
        }
        return true;
    }

    /* User home directories: /home/<user> (exactly 3 components) */
    if (strncmp(path, "/home/", 6) == 0) {
        char username[256];
        if (extract_username(path, username, sizeof(username))) {
            uint32_t h = kbox_hash_username(username);
            uint32_t id = 1000 + (h % 64000);
            *mode = 0700;
            *uid = id;
            *gid = id;
            return true;
        }
    }

    /* /root */
    if (strcmp(path, "/root") == 0) {
        *mode = 0700;
        *uid = 0;
        *gid = 0;
        return true;
    }

    return false;
}

int kbox_parse_change_id(const char *spec, uid_t *uid, gid_t *gid)
{
    if (!spec || !uid || !gid)
        return -1;

    const char *colon = strchr(spec, ':');
    if (!colon || colon == spec)
        return -1;

    char *end;
    unsigned long u, g;

    errno = 0;
    u = strtoul(spec, &end, 10);
    if (end != colon || errno != 0)
        return -1;

    errno = 0;
    g = strtoul(colon + 1, &end, 10);
    if (*end != '\0' || errno != 0)
        return -1;

    *uid = (uid_t) u;
    *gid = (gid_t) g;
    return 0;
}

#ifndef KBOX_UNIT_TEST
int kbox_apply_guest_identity(const struct kbox_sysnrs *s,
                              bool root_id,
                              uid_t override_uid,
                              gid_t override_gid)
{
    long uid, gid;
    long rc;

    if (root_id) {
        uid = 0;
        gid = 0;
    } else {
        uid = (long) override_uid;
        gid = (long) override_gid;
    }

    rc = kbox_lkl_setresgid(s, gid, gid, gid);
    if (rc < 0)
        return -1;

    rc = kbox_lkl_setresuid(s, uid, uid, uid);
    if (rc < 0)
        return -1;

    rc = kbox_lkl_setfsgid(s, gid);
    if (rc < 0)
        return -1;

    return 0;
}
#endif
