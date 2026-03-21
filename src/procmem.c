/* SPDX-License-Identifier: MIT */

/* Process memory access for seccomp-unotify.
 *
 * Wraps process_vm_readv/writev to read/write tracee memory without ptrace.
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "procmem.h"

int kbox_vm_read(pid_t pid, uint64_t remote_addr, void *out, size_t len)
{
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t ret;

    if (len == 0)
        return 0;

    local_iov.iov_base = out;
    local_iov.iov_len = len;
    remote_iov.iov_base = (void *) (uintptr_t) remote_addr;
    remote_iov.iov_len = len;

    ret = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (ret < 0)
        return -errno;
    if ((size_t) ret != len)
        return -EIO;
    return 0;
}

int kbox_vm_write(pid_t pid, uint64_t remote_addr, const void *in, size_t len)
{
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t ret;

    if (len == 0)
        return 0;

    /* process_vm_writev takes a non-const iov_base, but we only read from the
     * local buffer. The cast is safe.
     */
    local_iov.iov_base = (void *) (uintptr_t) in;
    local_iov.iov_len = len;
    remote_iov.iov_base = (void *) (uintptr_t) remote_addr;
    remote_iov.iov_len = len;

    ret = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (ret < 0)
        return -errno;
    if ((size_t) ret != len)
        return -EIO;
    return 0;
}

int kbox_vm_read_string(pid_t pid,
                        uint64_t remote_addr,
                        char *buf,
                        size_t max_len)
{
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t n;
    size_t i;

    if (remote_addr == 0)
        return -EFAULT;
    if (max_len == 0)
        return -EINVAL;

    local_iov.iov_base = buf;
    local_iov.iov_len = max_len;
    remote_iov.iov_base = (void *) (uintptr_t) remote_addr;
    remote_iov.iov_len = max_len;

    n = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (n <= 0)
        return errno ? -errno : -EIO;

    /* Find the NUL terminator within the bytes we actually read. */
    for (i = 0; i < (size_t) n; i++) {
        if (buf[i] == '\0')
            return (int) i;
    }

    /* No NUL found in the read data. Two possible reasons:
     *   - Short read (page boundary): tracee memory is faulted.
     *   - Full read: path exceeds PATH_MAX.
     *
     * Either way, do not silently truncate: a truncated path could resolve to
     * an unintended file.
     */
    buf[0] = '\0';
    if ((size_t) n < max_len)
        return -EFAULT;
    return -ENAMETOOLONG;
}

int kbox_vm_read_open_how(pid_t pid,
                          uint64_t remote_addr,
                          uint64_t size,
                          struct kbox_open_how *out)
{
    uint64_t expected = (uint64_t) sizeof(struct kbox_open_how);

    if (remote_addr == 0)
        return -EFAULT;
    if (size < expected)
        return -EINVAL;
    if (size > expected)
        return -E2BIG;

    memset(out, 0, sizeof(*out));
    return kbox_vm_read(pid, remote_addr, out, sizeof(*out));
}

int kbox_vm_write_force(pid_t pid,
                        uint64_t remote_addr,
                        const void *in,
                        size_t len)
{
    char proc_path[64];
    int fd;
    ssize_t n;

    if (len == 0)
        return 0;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/mem", (int) pid);
    fd = open(proc_path, O_WRONLY);
    if (fd < 0)
        return -errno;

    n = pwrite(fd, in, len, (off_t) remote_addr);
    close(fd);

    if (n < 0)
        return -errno;
    if ((size_t) n != len)
        return -EIO;
    return 0;
}
