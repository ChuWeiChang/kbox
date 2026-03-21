/* SPDX-License-Identifier: MIT */

#ifndef KBOX_PROCMEM_H
#define KBOX_PROCMEM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "lkl-wrap.h"

int kbox_vm_read(pid_t pid, uint64_t remote_addr, void *out, size_t len);
int kbox_vm_write(pid_t pid, uint64_t remote_addr, const void *in, size_t len);
int kbox_vm_write_force(pid_t pid,
                        uint64_t remote_addr,
                        const void *in,
                        size_t len);
int kbox_vm_read_string(pid_t pid,
                        uint64_t remote_addr,
                        char *buf,
                        size_t max_len);
int kbox_vm_read_open_how(pid_t pid,
                          uint64_t remote_addr,
                          uint64_t size,
                          struct kbox_open_how *out);

#endif /* KBOX_PROCMEM_H */
