/* SPDX-License-Identifier: MIT */
#ifndef KBOX_IO_UTIL_H
#define KBOX_IO_UTIL_H

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

static inline ssize_t pread_full(int fd,
                                 unsigned char *buf,
                                 size_t size,
                                 off_t off)
{
    size_t total = 0;

    while (total < size) {
        ssize_t nr = pread(fd, buf + total, size - total, off + (off_t) total);

        if (nr < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (nr == 0)
            break;
        total += (size_t) nr;
    }

    return (ssize_t) total;
}

#endif /* KBOX_IO_UTIL_H */
