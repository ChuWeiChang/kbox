/* SPDX-License-Identifier: MIT */

#ifndef KBOX_PROBE_H
#define KBOX_PROBE_H

/* Runtime host feature probing.
 *
 * Verify at startup that the host kernel supports the features kbox depends on.
 * Fail fast with a clear diagnostic if any check fails.
 */

/* Run all probes.
 * Returns 0 on success, -1 if a required feature is unavailable.
 * Prints diagnostics to stderr.
 */
int kbox_probe_host_features(void);

#endif /* KBOX_PROBE_H */
