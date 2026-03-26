/* SPDX-License-Identifier: MIT */
/* Guest benchmark: measure per-syscall latency for core operations.
 *
 * Runs each syscall in a tight loop (default 10000 iterations) and reports
 * average wall-clock time in microseconds.  Designed to run inside kbox
 * against an ext4 rootfs, and on bare metal for comparison.
 *
 * Usage: bench_test [iterations]
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_ITERS 10000

static long elapsed_ns(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000000000L +
           (end->tv_nsec - start->tv_nsec);
}

static double bench_stat(int iters)
{
    struct timespec t0, t1;
    struct stat st;

    if (stat("/etc/hostname", &st) < 0)
        return -1.0;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iters; i++)
        stat("/etc/hostname", &st);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    return (double) elapsed_ns(&t0, &t1) / iters / 1000.0;
}

static double bench_open_close(int iters)
{
    struct timespec t0, t1;

    int probe = open("/etc/hostname", O_RDONLY);
    if (probe < 0)
        return -1.0;
    close(probe);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iters; i++) {
        int fd = open("/etc/hostname", O_RDONLY);
        if (fd >= 0)
            close(fd);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    return (double) elapsed_ns(&t0, &t1) / iters / 1000.0;
}

static double bench_lseek_read(int iters)
{
    struct timespec t0, t1;
    char buf[64];

    int fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0)
        return -1.0;

    volatile ssize_t sink;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iters; i++) {
        lseek(fd, 0, SEEK_SET);
        sink = read(fd, buf, sizeof(buf));
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    (void) sink;
    close(fd);
    return (double) elapsed_ns(&t0, &t1) / iters / 1000.0;
}

static double bench_write(int iters)
{
    struct timespec t0, t1;
    char buf[64];

    memset(buf, 'x', sizeof(buf));

    int fd = open("/tmp/bench_write", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1.0;

    volatile ssize_t sink;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iters; i++) {
        lseek(fd, 0, SEEK_SET);
        sink = write(fd, buf, sizeof(buf));
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    (void) sink;
    close(fd);
    unlink("/tmp/bench_write");
    return (double) elapsed_ns(&t0, &t1) / iters / 1000.0;
}

static double bench_getpid(int iters)
{
    struct timespec t0, t1;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iters; i++)
        getpid();
    clock_gettime(CLOCK_MONOTONIC, &t1);

    return (double) elapsed_ns(&t0, &t1) / iters / 1000.0;
}

int main(int argc, char *argv[])
{
    int iters = DEFAULT_ITERS;

    if (argc > 1)
        iters = atoi(argv[1]);
    if (iters <= 0)
        iters = DEFAULT_ITERS;

    printf("syscall microbenchmark (%d iterations)\n", iters);
    printf("%-16s %10s\n", "syscall", "us/call");
    printf("%-16s %10s\n", "-------", "-------");

    struct {
        const char *name;
        double (*fn)(int);
    } benches[] = {
        {"stat", bench_stat},
        {"open+close", bench_open_close},
        {"lseek+read", bench_lseek_read},
        {"write", bench_write},
        {"getpid", bench_getpid},
    };
    for (size_t i = 0; i < sizeof(benches) / sizeof(benches[0]); i++) {
        double us = benches[i].fn(iters);
        if (us < 0)
            printf("%-16s %10s\n", benches[i].name, "SKIP");
        else
            printf("%-16s %10.1f\n", benches[i].name, us);
    }

    printf("PASS: bench_test\n");
    return 0;
}
