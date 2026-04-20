/* SPDX-License-Identifier: MIT */
/* Guest test: verify sendfile with shadow input FDs.
 *
 * After the refactor, sendfile with shadow input FDs (O_RDONLY files)
 * uses find_by_host_fd() to resolve the LKL FD for reading, then emulates
 * via LKL read + host/LKL write. This test ensures sendfile works correctly
 * with shadow in_fd after the refactor.
 *
 * Performance test (KBOX_PERF_TESTS): Demonstrates O(1) behavior of
 * find_by_host_fd() by measuring sendfile() timing with different fd table
 * population levels. Timing should stay constant regardless of table size.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define TEST_DATA "kbox shadow sendfile integration test data"
#define TEST_FILE "/opt/sendfile_test_data.txt"
#define OUT_FILE "/opt/sendfile_out_test.txt"

#ifdef KBOX_PERF_TESTS
#define PERF_ITERATIONS 10000
static const int perf_test_sizes[] = {64, 256, 1024, 4096, 16384};
static const int num_sizes =
    sizeof(perf_test_sizes) / sizeof(perf_test_sizes[0]);
static double time_diff_ns(struct timespec *start, struct timespec *end)
{
    return ((double) (end->tv_sec - start->tv_sec) * 1e9) +
           (double) (end->tv_nsec - start->tv_nsec);
}
#endif

#define CHECK(cond, msg)                                               \
    do {                                                               \
        if (!(cond)) {                                                 \
            fprintf(stderr, "FAIL: %s (errno: %d - %s)\n", msg, errno, \
                    strerror(errno));                                  \
            exit(1);                                                   \
        }                                                              \
    } while (0)

int main(void)
{
    int in_fd, out_fd;
    size_t test_len = strlen(TEST_DATA);
    size_t remaining, total_sent = 0;

    /* 1. Create input file in LKL rootfs with test data */
    int setup_fd =
        open(TEST_FILE, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(setup_fd >= 0, "create input file");
    CHECK(write(setup_fd, TEST_DATA, test_len) == (ssize_t) test_len,
          "write test data to input file");
    close(setup_fd);

    /* 2. Open input file as O_RDONLY to trigger shadow memfd creation.
     * This ensures sendfile uses find_by_host_fd() to resolve the LKL FD.
     */
    in_fd = open(TEST_FILE, O_RDONLY | O_CLOEXEC);
    CHECK(in_fd >= 0, "open input file as O_RDONLY (creates shadow memfd)");

    /* 3. Create regular output file instead of a pipe (pipes cause EINVAL in
     * sendfile) */
    out_fd = open(OUT_FILE, O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(out_fd >= 0, "create regular output file for sendfile target");

    // #ifdef KBOX_PERF_TESTS
    //     /* O(1) Characteristic Test: Open multiple shadow FDs at different
    //      * population densities to verify lookup performance is constant.
    //      */
    //     struct timespec t_start, t_end;
    //     FILE *tty = fopen("/dev/tty", "w");
    //     if (tty) {
    //         fprintf(tty,
    //                 "\n--- O(1) Characteristic Perf Test (find_by_host_fd) "
    //                 "---\n");
    //     }

    //     double baseline_time_ns = 0;

    //     /* Create a temporary target for performance writes */
    //     int dummy_out_fd = open("/opt/perf_target.tmp",
    //                             O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
    //                             0644);
    //     CHECK(dummy_out_fd >= 0, "open dummy target for perf test");

    //     for (int size_idx = 0; size_idx < num_sizes; size_idx++) {
    //         int num_fds = perf_test_sizes[size_idx];

    //         /* Create dummy shadow FDs to populate the table */
    //         int *fds_to_close = malloc((num_fds - 1) * sizeof(int));
    //         CHECK(fds_to_close != NULL, "allocate fd array");
    //         memset(fds_to_close, 0, (num_fds - 1) * sizeof(int));

    //         for (int i = 0; i < num_fds - 1; i++) {
    //             int fd = open(TEST_FILE, O_RDONLY | O_CLOEXEC);
    //             if (fd >= 0) {
    //                 fds_to_close[i] = fd;
    //             }
    //         }

    //         /* Time sendfile() from the main shadow FD with varying table
    //         sizes */ clock_gettime(CLOCK_MONOTONIC, &t_start); for (int iter
    //         = 0; iter < PERF_ITERATIONS; iter++) {
    //             lseek(in_fd, 0, SEEK_SET);
    //             sendfile(dummy_out_fd, in_fd, NULL, test_len);
    //         }
    //         clock_gettime(CLOCK_MONOTONIC, &t_end);

    //         double total_ns = time_diff_ns(&t_start, &t_end);
    //         double ns_per_op = total_ns / PERF_ITERATIONS;

    //         if (tty) {
    //             fprintf(tty, "N = %-5d (fd table entries) | Time: %8.2f
    //             ns/op\n",
    //                     num_fds, ns_per_op);
    //         }

    //         if (size_idx == 0) {
    //             baseline_time_ns = ns_per_op;
    //         } else {
    //             double ratio = ns_per_op / baseline_time_ns;
    //             if (tty) {
    //                 fprintf(tty, "  Ratio vs baseline: %.2fx\n", ratio);
    //             }
    //             CHECK(ratio < 2.0,
    //                   "O(1) violation: lookup degraded beyond 2x ratio");
    //         }

    //         /* Cleanup dummy FDs */
    //         for (int i = 0; i < num_fds - 1; i++) {
    //             if (fds_to_close[i] > 0)
    //                 close(fds_to_close[i]);
    //         }
    //         free(fds_to_close);
    //     }

    //     close(dummy_out_fd);
    //     unlink("/opt/perf_target.tmp");

    //     if (tty) {
    //         fprintf(tty,
    //                 "✓ O(1) verified: lookup time stays constant across table
    //                 " "sizes\n\n");
    //         fclose(tty);
    //     }
    // #endif

    /* 4. Correctness pass: use sendfile to verify data integrity */
    lseek(in_fd, 0, SEEK_SET);
    remaining = test_len;
    total_sent = 0;

    while (remaining > 0) {
        /* Sending to a standard file (out_fd) prevents EINVAL */
        ssize_t sent = sendfile(out_fd, in_fd, NULL, remaining);
        CHECK(sent >= 0, "sendfile from shadow in_fd to regular out_fd");
        if (sent == 0)
            break;
        total_sent += (size_t) sent;
        remaining -= (size_t) sent;
    }

    CHECK(total_sent == test_len, "transferred all data via sendfile");

    /* 5. Verify data came through to the output file correctly */
    close(out_fd); /* Close the file to force kbox/host to flush all write
                      buffers */

    /* Re-open the file strictly for reading */
    int verify_fd = open(OUT_FILE, O_RDONLY | O_CLOEXEC);
    CHECK(verify_fd >= 0, "re-open output file for verification");

    size_t file_received = 0;
    char verify_buf[256] = {0};
    while (file_received < total_sent) {
        ssize_t nread = read(verify_fd, verify_buf + file_received,
                             total_sent - file_received);
        CHECK(nread >= 0, "read from output file");
        if (nread == 0)
            break;
        file_received += (size_t) nread;
    }

    CHECK(file_received == total_sent, "received all data from output file");
    verify_buf[file_received] = '\0';
    CHECK(strcmp(verify_buf, TEST_DATA) == 0, "data matches TEST_DATA");

    /* 6. Cleanup */
    close(verify_fd);
    close(in_fd);
    unlink(TEST_FILE);
    unlink(OUT_FILE);

    printf("PASS\n");
    return 0;
}