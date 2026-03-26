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
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include "procmem.h"

static inline pid_t guest_pid(const struct kbox_guest_mem *guest)
{
    return (pid_t) guest->opaque;
}

static int ensure_self_mem_fd(void)
{
    static int self_mem_fd = -1;
    int fd = __atomic_load_n(&self_mem_fd, __ATOMIC_ACQUIRE);

    if (fd >= 0)
        return fd;

    fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;

    {
        int expected = -1;
        if (!__atomic_compare_exchange_n(&self_mem_fd, &expected, fd, 0,
                                         __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
            close(fd);
            fd = expected;
        }
    }

    return fd;
}

static int self_mem_read(uint64_t remote_addr, void *out, size_t len)
{
    int fd;
    ssize_t ret;

    if (len == 0)
        return 0;
    if (remote_addr == 0 || !out)
        return -EFAULT;

    fd = ensure_self_mem_fd();
    if (fd < 0)
        return -errno;

    ret = pread(fd, out, len, (off_t) remote_addr);
    if (ret < 0)
        return -errno;
    if ((size_t) ret != len)
        return -EIO;
    return 0;
}

static int self_mem_read_string(uint64_t remote_addr, char *buf, size_t max_len)
{
    int fd;
    size_t total = 0;

    enum {
        KBOX_STRING_READ_CHUNK = 256,
    };

    if (remote_addr == 0)
        return -EFAULT;
    if (max_len == 0)
        return -EINVAL;

    fd = ensure_self_mem_fd();
    if (fd < 0)
        return -errno;

    while (total < max_len) {
        ssize_t n;
        size_t i;
        size_t chunk = max_len - total;

        if (chunk > KBOX_STRING_READ_CHUNK)
            chunk = KBOX_STRING_READ_CHUNK;

        n = pread(fd, buf + total, chunk, (off_t) (remote_addr + total));
        if (n < 0)
            return -errno;
        if (n == 0)
            return -EIO;

        for (i = 0; i < (size_t) n; i++) {
            if (buf[total + i] == '\0')
                return (int) (total + i);
        }

        total += (size_t) n;

        if ((size_t) n < chunk)
            return -EFAULT;
    }

    if (max_len > 0)
        buf[0] = '\0';
    return -ENAMETOOLONG;
}

int kbox_current_read(uint64_t remote_addr, void *out, size_t len)
{
    return self_mem_read(remote_addr, out, len);
}

int kbox_current_write(uint64_t remote_addr, const void *in, size_t len)
{
    return kbox_vm_write(getpid(), remote_addr, in, len);
}

int kbox_current_write_force(uint64_t remote_addr, const void *in, size_t len)
{
    static const char proc_self_mem[] = "/proc/self/mem";
    int fd;
    ssize_t n;

    if (len == 0)
        return 0;
    if (remote_addr == 0 || !in)
        return -EFAULT;

    fd = open(proc_self_mem, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;

    n = pwrite(fd, in, len, (off_t) remote_addr);
    if (n < 0) {
        int saved_errno = errno;
        close(fd);
        return -saved_errno;
    }
    close(fd);

    if ((size_t) n != len)
        return -EIO;
    return 0;
}

int kbox_current_read_string(uint64_t remote_addr, char *buf, size_t max_len)
{
    return self_mem_read_string(remote_addr, buf, max_len);
}

int kbox_current_read_open_how(uint64_t remote_addr,
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
    return kbox_current_read(remote_addr, out, sizeof(*out));
}

int kbox_vm_read(pid_t pid, uint64_t remote_addr, void *out, size_t len)
{
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t ret;

    if (len == 0)
        return 0;
    if (remote_addr == 0 || !out)
        return -EFAULT;

    local_iov.iov_base = out;
    local_iov.iov_len = len;
    remote_iov.iov_base = (void *) (uintptr_t) remote_addr;
    remote_iov.iov_len = len;

    ret = syscall(SYS_process_vm_readv, pid, &local_iov, 1, &remote_iov, 1, 0);
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
    if (remote_addr == 0 || !in)
        return -EFAULT;

    /* process_vm_writev takes a non-const iov_base, but we only read from the
     * local buffer. The cast is safe.
     */
    local_iov.iov_base = (void *) (uintptr_t) in;
    local_iov.iov_len = len;
    remote_iov.iov_base = (void *) (uintptr_t) remote_addr;
    remote_iov.iov_len = len;

    ret = syscall(SYS_process_vm_writev, pid, &local_iov, 1, &remote_iov, 1, 0);
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
    size_t total = 0;

    enum {
        KBOX_STRING_READ_CHUNK = 256,
    };

    if (remote_addr == 0)
        return -EFAULT;
    if (max_len == 0)
        return -EINVAL;

    while (total < max_len) {
        ssize_t n;
        size_t i;
        size_t chunk = max_len - total;

        if (chunk > KBOX_STRING_READ_CHUNK)
            chunk = KBOX_STRING_READ_CHUNK;

        local_iov.iov_base = buf + total;
        local_iov.iov_len = chunk;
        remote_iov.iov_base =
            (void *) (uintptr_t) (remote_addr + (uint64_t) total);
        remote_iov.iov_len = chunk;

        n = syscall(SYS_process_vm_readv, pid, &local_iov, 1, &remote_iov, 1,
                    0);
        if (n <= 0)
            return errno ? -errno : -EIO;

        for (i = 0; i < (size_t) n; i++) {
            if (buf[total + i] == '\0')
                return (int) (total + i);
        }

        total += (size_t) n;

        /* Short read before NUL means the next page isn't readable. */
        if ((size_t) n < chunk)
            return -EFAULT;
    }

    if (max_len > 0)
        buf[0] = '\0';
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
    if (remote_addr == 0 || !in)
        return -EFAULT;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/mem", (int) pid);
    fd = open(proc_path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;

    n = pwrite(fd, in, len, (off_t) remote_addr);
    if (n < 0) {
        int saved_errno = errno;
        close(fd);
        return -saved_errno;
    }
    close(fd);
    if ((size_t) n != len)
        return -EIO;
    return 0;
}

static int process_vm_guest_read(const struct kbox_guest_mem *guest,
                                 uint64_t remote_addr,
                                 void *out,
                                 size_t len)
{
    return kbox_vm_read(guest_pid(guest), remote_addr, out, len);
}

static int process_vm_guest_write(const struct kbox_guest_mem *guest,
                                  uint64_t remote_addr,
                                  const void *in,
                                  size_t len)
{
    return kbox_vm_write(guest_pid(guest), remote_addr, in, len);
}

static int process_vm_guest_write_force(const struct kbox_guest_mem *guest,
                                        uint64_t remote_addr,
                                        const void *in,
                                        size_t len)
{
    return kbox_vm_write_force(guest_pid(guest), remote_addr, in, len);
}

static int process_vm_guest_read_string(const struct kbox_guest_mem *guest,
                                        uint64_t remote_addr,
                                        char *buf,
                                        size_t max_len)
{
    return kbox_vm_read_string(guest_pid(guest), remote_addr, buf, max_len);
}

static int process_vm_guest_read_open_how(const struct kbox_guest_mem *guest,
                                          uint64_t remote_addr,
                                          uint64_t size,
                                          struct kbox_open_how *out)
{
    return kbox_vm_read_open_how(guest_pid(guest), remote_addr, size, out);
}

static int current_guest_read(const struct kbox_guest_mem *guest,
                              uint64_t remote_addr,
                              void *out,
                              size_t len)
{
    (void) guest;
    return kbox_current_read(remote_addr, out, len);
}

static int current_guest_write(const struct kbox_guest_mem *guest,
                               uint64_t remote_addr,
                               const void *in,
                               size_t len)
{
    (void) guest;
    return kbox_current_write(remote_addr, in, len);
}

static int current_guest_write_force(const struct kbox_guest_mem *guest,
                                     uint64_t remote_addr,
                                     const void *in,
                                     size_t len)
{
    (void) guest;
    return kbox_current_write_force(remote_addr, in, len);
}

static int current_guest_read_string(const struct kbox_guest_mem *guest,
                                     uint64_t remote_addr,
                                     char *buf,
                                     size_t max_len)
{
    (void) guest;
    return kbox_current_read_string(remote_addr, buf, max_len);
}

static int current_guest_read_open_how(const struct kbox_guest_mem *guest,
                                       uint64_t remote_addr,
                                       uint64_t size,
                                       struct kbox_open_how *out)
{
    (void) guest;
    return kbox_current_read_open_how(remote_addr, size, out);
}

const struct kbox_guest_mem_ops kbox_process_vm_guest_mem_ops = {
    .read = process_vm_guest_read,
    .write = process_vm_guest_write,
    .write_force = process_vm_guest_write_force,
    .read_string = process_vm_guest_read_string,
    .read_open_how = process_vm_guest_read_open_how,
};

const struct kbox_guest_mem_ops kbox_current_guest_mem_ops = {
    .read = current_guest_read,
    .write = current_guest_write,
    .write_force = current_guest_write_force,
    .read_string = current_guest_read_string,
    .read_open_how = current_guest_read_open_how,
};

int kbox_guest_mem_read(const struct kbox_guest_mem *guest,
                        uint64_t remote_addr,
                        void *out,
                        size_t len)
{
    if (!guest || !guest->ops || !guest->ops->read)
        return -EINVAL;
    return guest->ops->read(guest, remote_addr, out, len);
}

int kbox_guest_mem_write(const struct kbox_guest_mem *guest,
                         uint64_t remote_addr,
                         const void *in,
                         size_t len)
{
    if (!guest || !guest->ops || !guest->ops->write)
        return -EINVAL;
    return guest->ops->write(guest, remote_addr, in, len);
}

int kbox_guest_mem_write_force(const struct kbox_guest_mem *guest,
                               uint64_t remote_addr,
                               const void *in,
                               size_t len)
{
    if (!guest || !guest->ops || !guest->ops->write_force)
        return -EINVAL;
    return guest->ops->write_force(guest, remote_addr, in, len);
}

int kbox_guest_mem_read_string(const struct kbox_guest_mem *guest,
                               uint64_t remote_addr,
                               char *buf,
                               size_t max_len)
{
    if (!guest || !guest->ops || !guest->ops->read_string)
        return -EINVAL;
    return guest->ops->read_string(guest, remote_addr, buf, max_len);
}

int kbox_guest_mem_read_open_how(const struct kbox_guest_mem *guest,
                                 uint64_t remote_addr,
                                 uint64_t size,
                                 struct kbox_open_how *out)
{
    if (!guest || !guest->ops || !guest->ops->read_open_how)
        return -EINVAL;
    return guest->ops->read_open_how(guest, remote_addr, size, out);
}
