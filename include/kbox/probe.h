/* SPDX-License-Identifier: MIT */

#ifndef KBOX_PROBE_H
#define KBOX_PROBE_H

#include "kbox/cli.h"

struct kbox_probe_result {
    int no_new_privs_ok;
    int seccomp_filter_ok;
    int seccomp_listener_ok;
    int process_vm_readv_ok;
};

/* Runtime host feature probing.
 *
 * Verify at startup that the host kernel supports the features kbox depends on.
 * Fail fast with a clear diagnostic if any check fails.
 *
 * All modes require basic seccomp filter support plus no_new_privs.
 * SECCOMP and AUTO additionally require seccomp-unotify + process_vm_readv
 * because they run the supervisor path today. TRAP and REWRITE skip those
 * supervisor-specific probes.
 */

/* Run all probes for the given syscall mode.
 * Returns 0 on success, -1 if a required feature is unavailable.
 * Prints diagnostics to stderr.
 */
int kbox_probe_host_features(enum kbox_syscall_mode mode);
int kbox_collect_probe_result(enum kbox_syscall_mode mode,
                              struct kbox_probe_result *out);

#endif /* KBOX_PROBE_H */
