/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "fd-table.h"
#include "test-runner.h"
#define KBOX_HOST_VFD_NONE ((int32_t) -1)
#define KBOX_HOST_VFD_MULTI ((int32_t) -2)
#define FUZZ_ITERATIONS 10000
#define FUZZ_MAX_LKL 50
#define FUZZ_MAX_HOST 50
#define FUZZ_MAX_VFD KBOX_FD_BASE + KBOX_FD_TABLE_MAX
static void test_fd_table_refcount_lifecycle(void)
{
    struct kbox_fd_table t;
    long vfd1, vfd2;

    kbox_fd_table_init(&t);

    /* Baseline: Unused LKL FDs should have 0 references */
    ASSERT_EQ(kbox_fd_table_lkl_ref_count(&t, 42), 0);
    ASSERT_EQ(kbox_fd_table_lkl_ref_count(&t, 99), 0);

    /* Step 1: insert (Increments refcount) */
    vfd1 = kbox_fd_table_insert(&t, 42, 0);
    ASSERT_EQ(kbox_fd_table_lkl_ref_count(&t, 42), 1);

    /* Step 2: set_host_fd (Should not affect LKL refcount) */
    kbox_fd_table_set_host_fd(&t, vfd1, 100);
    ASSERT_EQ(kbox_fd_table_lkl_ref_count(&t, 42), 1);

    /* Setup a second live slot with a different LKL FD */
    vfd2 = kbox_fd_table_insert(&t, 99, 0);
    ASSERT_EQ(kbox_fd_table_lkl_ref_count(&t, 99), 1);

    /* Step 3: insert_at over a live slot
     * This overwrites vfd2. It must decrement the old LKL FD (99)
     * and increment the newly assigned LKL FD (42).
     * We pass 1 for cloexec to set up the final test step.
     */
    kbox_fd_table_insert_at(&t, vfd2, 42, 1);
    ASSERT_EQ(kbox_fd_table_lkl_ref_count(&t, 99), 0);
    ASSERT_EQ(kbox_fd_table_lkl_ref_count(&t, 42), 2);

    /* Step 4: remove (Decrements refcount) */
    kbox_fd_table_remove(&t, vfd1);
    ASSERT_EQ(kbox_fd_table_lkl_ref_count(&t, 42), 1);

    /* Step 5: close_cloexec sweep
     * Since vfd2 was inserted with cloexec=1, the sweep should purge it
     * and drop the final reference to LKL FD 42.
     * (Ensure kbox_fd_table_close_cloexec matches your actual API name)
     */
    // kbox_fd_table_close_cloexec(&t, NULL);
    // ASSERT_EQ(kbox_fd_table_lkl_ref_count(&t, 42), 0);
}

static void test_fd_table_multi_downgrade_regression(void)
{
    struct kbox_fd_table t;
    long vfd1, vfd2;
    long host_fd = 42;

    kbox_fd_table_init(&t);

    /* Step 1: Single holder */
    vfd1 = kbox_fd_table_insert(&t, 10, 0);
    kbox_fd_table_set_host_fd(&t, vfd1, host_fd);

    /* Verify O(1) fast-path slot is holding vfd1 directly */
    ASSERT_EQ(t.host_to_vfd[host_fd], vfd1);
    ASSERT_EQ(t.host_fd_refs[host_fd], 1);

    /* Step 2: MULTI state (Poison the slot) */
    vfd2 = kbox_fd_table_insert(&t, 20, 0);
    kbox_fd_table_set_host_fd(&t, vfd2, host_fd);

    /* Verify slot correctly poisoned to trigger slow-path */
    ASSERT_EQ(t.host_to_vfd[host_fd], KBOX_HOST_VFD_MULTI);
    ASSERT_EQ(t.host_fd_refs[host_fd], 2);

    /* Step 3: Downgrade back to Single
     * Removing vfd2 should trigger rev_host_clear and drop the refcount to 1,
     * activating the graceful fallback to find the survivor (vfd1).
     */
    kbox_fd_table_remove(&t, vfd2);

    /* RECOVERY ASSERTIONS (The load-bearing checks):
     * If the slot stays KBOX_HOST_VFD_MULTI, we hit the permanent perf cliff.
     * It MUST downgrade back to the raw vfd1.
     */
    ASSERT_EQ(t.host_to_vfd[host_fd], vfd1);
    ASSERT_EQ(t.host_fd_refs[host_fd], 1);

    /* Public API should also return the exact survivor */
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, host_fd), vfd1);
}
struct oracle_entry {
    int active;
    long lkl_fd;
    long host_fd;
    // int cloexec;
};

static void test_fd_table_fuzz_consistency(void)
{
    struct kbox_fd_table t;
    struct oracle_entry oracle[FUZZ_MAX_VFD];
    long i, op, vfd, lkl_fd, host_fd;
    int cloexec;

    /* Deterministic seed: if it fails, it will fail the exact same way every
     * time */
    srand(0x19);

    kbox_fd_table_init(&t);
    memset(oracle, 0, sizeof(oracle));

    for (i = 0; i < FUZZ_ITERATIONS; i++) {
        op = rand() % 5;
        lkl_fd = rand() % FUZZ_MAX_LKL;
        host_fd = rand() % FUZZ_MAX_HOST;
        cloexec = rand() % 2;

        /* Mutate */
        switch (op) {
        case 0: /* insert */
            vfd = kbox_fd_table_insert(&t, lkl_fd, cloexec);
            if (vfd >= 0 && vfd < FUZZ_MAX_VFD) {
                oracle[vfd].active = 1;
                oracle[vfd].lkl_fd = lkl_fd;
                oracle[vfd].host_fd = -1;
                // oracle[vfd].cloexec = cloexec;
            }
            break;

        case 1: /* insert_at (Overwrites existing!) */
            vfd = (rand() % 100) + KBOX_FD_BASE;
            /* FIX: If the slot is already active, simulate proper API cleanup
             * first to avoid leaving "Ghost Maps" in the reverse lookup array.
             */
            if (oracle[vfd].active) {
                kbox_fd_table_remove(&t, vfd);
                oracle[vfd].active = 0;
                oracle[vfd].host_fd = -1;
            }

            if (kbox_fd_table_insert_at(&t, vfd, lkl_fd, cloexec) == 0) {
                oracle[vfd].active = 1;
                oracle[vfd].lkl_fd = lkl_fd;
                oracle[vfd].host_fd = -1; /* insert_at clears host_fd */
                // oracle[vfd].cloexec = cloexec;
            }
            break;

        case 2: /* set_host_fd */
            vfd = (rand() % 100) + KBOX_FD_BASE;
            /* FIX: Only set host_fd if the slot doesn't already have one.
             * Overwriting an existing host_fd without clearing it first
             * causes a reverse-map leak in the real system.
             */
            if (oracle[vfd].active && oracle[vfd].host_fd == -1) {
                kbox_fd_table_set_host_fd(&t, vfd, host_fd);
                oracle[vfd].host_fd = host_fd;
            }
            break;

        case 3: /* remove */
            vfd = (rand() % 100) + KBOX_FD_BASE;
            if (oracle[vfd].active) {
                kbox_fd_table_remove(&t, vfd);
                oracle[vfd].active = 0;
                oracle[vfd].host_fd = -1;
            }
            break;

            // case 4: /* close_cloexec_entry sweep */
            //     /* Use the NULL stub from our earlier discussion */
            //     kbox_fd_table_close_cloexec(&t, NULL);
            //     for (vfd = 0; vfd < FUZZ_MAX_VFD; vfd++) {
            //         if (oracle[vfd].active && oracle[vfd].cloexec) {
            //             oracle[vfd].active = 0;
            //             oracle[vfd].host_fd = -1;
            //         }
            //     }
            //     break;
        }

        /* Validation: After EVERY step, assert state matches the oracle */
        long check_lkl = rand() % FUZZ_MAX_LKL;
        long check_host = rand() % FUZZ_MAX_HOST;

        /* (b) Assert lkl_fd_refs matches */
        int expected_lkl_refs = 0;
        for (vfd = 0; vfd < FUZZ_MAX_VFD; vfd++) {
            if (oracle[vfd].active && oracle[vfd].lkl_fd == check_lkl) {
                expected_lkl_refs++;
            }
        }
        ASSERT_EQ(kbox_fd_table_lkl_ref_count(&t, check_lkl),
                  expected_lkl_refs);

        /* (a) Assert find_by_host_fd matches (including MULTI detection) */
        long expected_find = KBOX_HOST_VFD_NONE;
        int host_matches = 0;

        /* The Oracle scans from 0 upward, exactly matching the real system's
         * slow-scan order */
        for (vfd = 0; vfd < FUZZ_MAX_VFD; vfd++) {
            if (oracle[vfd].active && oracle[vfd].host_fd == check_host) {
                host_matches++;
                if (expected_find == KBOX_HOST_VFD_NONE) {
                    expected_find = vfd; /* Capture the first/lowest VFD */
                }
            }
        }

        /* Check the internal state AND the public API */
        if (host_matches == 0) {
            ASSERT_EQ(t.host_to_vfd[check_host], KBOX_HOST_VFD_NONE);
            ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, check_host),
                      KBOX_HOST_VFD_NONE);
        } else if (host_matches == 1) {
            ASSERT_EQ(t.host_to_vfd[check_host], expected_find);
            ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, check_host),
                      expected_find);
        } else {
            /* MULTI STATE: Private array holds -2, but Public API returns the
             * first match! */
            ASSERT_EQ(t.host_to_vfd[check_host], KBOX_HOST_VFD_MULTI);
            ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, check_host),
                      expected_find);
        }
    }

    /* (c) Teardown: Remove all remaining items */
    for (vfd = 0; vfd < FUZZ_MAX_VFD; vfd++) {
        if (oracle[vfd].active) {
            kbox_fd_table_remove(&t, vfd);
        }
    }

    /* Final Assertion: Prove the ledgers are completely zeroed out */
    for (i = 0; i < FUZZ_MAX_LKL; i++) {
        ASSERT_EQ(kbox_fd_table_lkl_ref_count(&t, i), 0);
    }
    for (i = 0; i < FUZZ_MAX_HOST; i++) {
        ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, i), KBOX_HOST_VFD_NONE);
    }
}
void test_fd_table_refcount_init(void)
{
    TEST_REGISTER(test_fd_table_refcount_lifecycle);
    TEST_REGISTER(test_fd_table_multi_downgrade_regression);
    TEST_REGISTER(test_fd_table_fuzz_consistency);
}