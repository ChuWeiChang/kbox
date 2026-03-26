# Syscall Behavioral Parity Spec -- MVP Set

Acceptance test definition for the C rewrite. For each syscall in the MVP
set, documents: arguments, return value, errno, side effects, and any
deviation from the Rust implementation.

Status: all syscalls below are implemented in seccomp-dispatch.c via
kbox_dispatch_request(). The same dispatch engine handles all three
interception tiers (seccomp-unotify, SIGSYS trap, binary rewriting).

## Notation

- `vfd`: virtual file descriptor (32768+), mapped to LKL-internal fd
- `LKL(...)`: forwarded to LKL via lkl_syscall6()
- `CONTINUE`: host kernel handles (seccomp: FLAG_CONTINUE; trap: re-issue via asm trampoline)
- `RETURN(val)`: injected return value
- `ERRNO(e)`: return with error = e

---

## File Open/Create

### openat (nr 257 x86_64 / 56 aarch64)
- args: dirfd, pathname_ptr, flags, mode
- behavior: read pathname from tracee, translate path for LKL, open via LKL, allocate vfd
- return: vfd on success, ERRNO on failure
- side effects: fd_table entry created; if O_CLOEXEC in flags, cloexec flag set
- special: virtual paths (/proc, /sys, /dev) -> CONTINUE; TTY paths -> CONTINUE
- errno: EMFILE (fd_table full), plus any LKL errno (ENOENT, EACCES, etc.)

### openat2 (nr 437 x86_64 / 437 aarch64)
- args: dirfd, pathname_ptr, open_how_ptr, size
- behavior: read pathname + open_how struct from tracee, delegate to openat logic
- return: vfd on success
- fallback: if LKL returns ENOSYS, falls back to openat with equivalent flags
- errno: EOPNOTSUPP if resolve != 0 and LKL lacks openat2

### open (nr 2 x86_64 only -- legacy)
- args: pathname_ptr, flags, mode
- behavior: maps to openat(AT_FDCWD, ...)
- return: same as openat

### close (nr 3 x86_64 / 57 aarch64)
- args: fd
- behavior: if fd is vfd, remove from fd_table, close LKL fd; else CONTINUE
- return: 0 on success, ERRNO on failure

---

## I/O

### read (nr 0 x86_64 / 63 aarch64)
- args: fd, buf_ptr, count
- behavior: if vfd, read from LKL in 128KB chunks, write to tracee via process_vm_writev
- return: bytes read (may be less than count), 0 on EOF
- special: chunked to avoid large single allocations
- errno: EBADF (not in fd_table)

### write (nr 1 x86_64 / 64 aarch64)
- args: fd, buf_ptr, count
- behavior: if vfd, read from tracee, write to LKL in 128KB chunks
- special: if fd is TTY-mirrored, also writes to host stdout/stderr
- return: bytes written (partial write returns count, not error)
- errno: EBADF (not in fd_table)

### pread64 (nr 17 x86_64 / 67 aarch64)
- args: fd, buf_ptr, count, offset
- behavior: positional read, does not update file offset
- return: bytes read

### lseek (nr 8 x86_64 / 62 aarch64)
- args: fd, offset, whence
- behavior: forward to LKL
- return: new offset from start

---

## FD Operations

### fcntl (nr 72 x86_64 / 25 aarch64)
- args: fd, cmd, arg
- behavior: F_DUPFD -> dup LKL fd, allocate new vfd >= arg; F_DUPFD_CLOEXEC -> same + set cloexec
- return: new vfd for F_DUPFD/F_DUPFD_CLOEXEC; CONTINUE for other cmds
- side effects: F_DUPFD_CLOEXEC sets cloexec flag in fd_table

### dup (nr 32 x86_64 / 23 aarch64)
- args: oldfd
- behavior: LKL dup, allocate new vfd
- return: new vfd

### dup2 (nr 33 x86_64 / -- aarch64 lacks dup2)
- args: oldfd, newfd
- behavior: atomically replace newfd mapping, dup LKL fd, close old LKL fd at newfd
- return: newfd (guest-side vfd)
- atomicity: dup first, then remove+close old mapping (not reverse)

### dup3 (nr 292 x86_64 / 24 aarch64)
- args: oldfd, newfd, flags
- behavior: like dup2 + O_CLOEXEC tracking
- return: newfd (guest-side vfd)

---

## Metadata

### fstat (nr 5 x86_64 / 80 aarch64)
- args: fd, statbuf_ptr
- behavior: if vfd, stat via LKL, write struct stat to tracee; else CONTINUE
- return: 0 on success

### newfstatat (nr 262 x86_64 / 79 aarch64)
- args: dirfd, pathname_ptr, statbuf_ptr, flags
- behavior: translate path, stat via LKL, write to tracee
- special: AT_EMPTY_PATH + vfd -> fstat shortcut
- return: 0 on success

### statx (nr 332 x86_64 / 291 aarch64)
- args: dirfd, pathname_ptr, flags, mask, statxbuf_ptr
- behavior: translate path, statx via LKL, write to tracee
- return: 0 on success

### faccessat2 (nr 439 x86_64 / 48 aarch64)
- args: dirfd, pathname_ptr, mode, flags
- behavior: translate path, check access via LKL
- return: 0 on success, ERRNO(EACCES) etc.

---

## Directory Operations

### getdents64 (nr 217 x86_64 / 61 aarch64)
- args: fd, dirp_ptr, count
- behavior: if vfd, read directory entries from LKL, write to tracee
- return: bytes of directory entries written

### getdents (nr 78 x86_64 / -- aarch64)
- args: same as getdents64
- behavior: same, for legacy getdents format

### mkdirat (nr 258 x86_64 / 34 aarch64)
- args: dirfd, pathname_ptr, mode
- behavior: translate path, mkdir via LKL
- return: 0 on success

### unlinkat (nr 263 x86_64 / 35 aarch64)
- args: dirfd, pathname_ptr, flags
- behavior: translate path, unlink or rmdir via LKL (AT_REMOVEDIR)
- return: 0 on success

### renameat2 (nr 316 x86_64 / 276 aarch64)
- args: olddirfd, oldpath_ptr, newdirfd, newpath_ptr, flags
- behavior: translate both paths, rename via LKL
- return: 0 on success

### fchmodat (nr 268 x86_64 / 53 aarch64)
- args: dirfd, pathname_ptr, mode, flags
- behavior: translate path, chmod via LKL
- return: 0 on success

### fchownat (nr 260 x86_64 / 54 aarch64)
- args: dirfd, pathname_ptr, owner, group, flags
- behavior: translate path, chown via LKL
- return: 0 on success

---

## Navigation

### chdir (nr 80 x86_64 / 49 aarch64)
- args: pathname_ptr
- behavior: translate path, chdir via LKL
- return: 0 on success
- side effects: LKL CWD updated

### fchdir (nr 81 x86_64 / 50 aarch64)
- args: fd
- behavior: if vfd, fchdir via LKL; else CONTINUE
- return: 0 on success

### getcwd (nr 79 x86_64 / 17 aarch64)
- args: buf_ptr, size
- behavior: getcwd from LKL, write to tracee
- return: length of CWD string on success

---

## Identity (Get)

### getuid/geteuid/getgid/getegid
- behavior: if root_identity, return 0; if override set, return override; if host_root mode, CONTINUE; else forward to LKL
- return: uid/gid value

### getresuid/getresgid
- behavior: write three uid/gid values to tracee pointers; same override logic
- return: 0 on success

### getgroups
- behavior: if root_identity, return group 0; if override, return override gid; else forward to LKL
- return: number of groups

---

## Identity (Set)

### setuid/setreuid/setresuid/setgid/setregid/setresgid/setgroups/setfsgid
- behavior: if root_identity or override, return 0 (suppress); if host_root, CONTINUE; else forward to LKL
- return: 0 on success
- side effects: LKL credential state updated (image mode)

---

## Mount

### mount (nr 165 x86_64 / 40 aarch64)
- args: source_ptr, target_ptr, fstype_ptr, flags, data_ptr
- behavior: translate target path, forward to LKL (including MS_BIND)
- return: 0 on success

### umount2 (nr 166 x86_64 / 39 aarch64)
- args: target_ptr, flags
- behavior: translate path, umount via LKL
- return: 0 on success

---

## Networking

### socket (nr 41 x86_64 / 198 aarch64)
- args: domain, type, protocol
- behavior: create socket via LKL, allocate vfd
- return: vfd on success

### connect (nr 42 x86_64 / 203 aarch64)
- args: sockfd, addr_ptr, addrlen
- behavior: if vfd, read sockaddr from tracee (capped at 4096 bytes), connect via LKL
- return: 0 on success

---

## Extended I/O

### pwrite64 (nr 18 x86_64 / 68 aarch64)
- args: fd, buf_ptr, count, offset
- behavior: positional write, does not update file offset; chunked like write
- return: bytes written

### writev (nr 20 x86_64 / 66 aarch64)
- args: fd, iov_ptr, iovcnt
- behavior: read iovec array from tracee, write each segment via LKL; TTY mirroring
- return: total bytes written across all segments
- limit: iovcnt capped at 1024

### readv (nr 19 x86_64 / 65 aarch64)
- args: fd, iov_ptr, iovcnt
- behavior: read from LKL into scatter buffers, write to tracee
- return: total bytes read

### ftruncate (nr 77 x86_64 / 46 aarch64)
- args: fd, length
- behavior: forward to LKL ftruncate
- return: 0 on success

### fallocate (nr 285 x86_64 / 47 aarch64)
- args: fd, mode, offset, len
- behavior: forward to LKL fallocate; returns ENOSYS if unsupported
- return: 0 on success

### flock (nr 73 x86_64 / 32 aarch64)
- args: fd, operation
- behavior: forward to LKL flock
- return: 0 on success

### ioctl (nr 16 x86_64 / 29 aarch64)
- args: fd, request, arg
- behavior: if vfd, return ENOTTY (regular files are not terminals); else CONTINUE
- return: ENOTTY for virtual FDs

---

## File Operations (Extended)

### readlinkat (nr 267 x86_64 / 78 aarch64)
- args: dirfd, pathname_ptr, buf_ptr, bufsiz
- behavior: translate path, readlinkat via LKL, write target to tracee
- return: length of link target

### pipe2 (nr 293 x86_64 / 59 aarch64)
- args: pipefd_ptr, flags
- behavior: create LKL pipe, allocate 2 virtual FDs, write to tracee
- return: 0 on success
- side effects: two fd_table entries created; O_CLOEXEC tracked if in flags

### pipe (nr 22 x86_64 only -- legacy)
- args: pipefd_ptr
- behavior: maps to pipe2 with flags=0
- return: 0 on success

### symlinkat (nr 266 x86_64 / 36 aarch64)
- args: target_ptr, newdirfd, linkpath_ptr
- behavior: translate link path, forward to LKL
- return: 0 on success

### linkat (nr 265 x86_64 / 37 aarch64)
- args: olddirfd, oldpath_ptr, newdirfd, newpath_ptr, flags
- behavior: translate both paths, forward to LKL
- return: 0 on success

### utimensat (nr 280 x86_64 / 88 aarch64)
- args: dirfd, pathname_ptr, times_ptr, flags
- behavior: translate path, read timespec array from tracee, forward to LKL
- return: 0 on success

---

## Time

### clock_gettime (nr 228 x86_64 / 113 aarch64)
- args: clockid, tp_ptr
- behavior: read host clock, write timespec to tracee memory
- return: 0 on success

### clock_getres (nr 229 x86_64 / 114 aarch64)
- args: clockid, res_ptr
- behavior: read host clock resolution, write to tracee memory
- return: 0 on success

### gettimeofday (nr 96 x86_64 only)
- args: tv_ptr, tz_ptr
- behavior: uses CLOCK_REALTIME, writes timeval + timezone to tracee
- return: 0 on success

---

## Process Info

### getpid / getppid / gettid
- behavior: return fixed values (getpid=1, getppid=0, gettid=1)
- return: fixed value

### umask (nr 95 x86_64 / 166 aarch64)
- args: mask
- behavior: forward to LKL umask
- return: previous umask value

### uname (nr 63 x86_64 / 160 aarch64)
- args: buf_ptr
- behavior: fill synthetic utsname (sysname="Linux", nodename="kbox",
  release="6.8.0-kbox", version="#1 SMP", machine=host arch), write to tracee
- return: 0 on success

### getrandom (nr 318 x86_64 / 278 aarch64)
- args: buf_ptr, buflen, flags
- behavior: read from LKL /dev/urandom, write to tracee; falls back to CONTINUE
- return: bytes filled

### prctl (nr 157 x86_64 / 167 aarch64)
- args: option, arg2, arg3, arg4, arg5
- behavior: PR_SET_NAME and PR_GET_NAME forwarded to LKL; all others CONTINUE
- return: 0 on success

---

## CONTINUE Passthrough

These syscalls are intercepted by the BPF filter but immediately returned
with FLAG_CONTINUE, letting the host kernel handle them:

- Signals: rt_sigaction, rt_sigprocmask, rt_sigreturn
- Threading: set_tid_address, set_robust_list, futex, clone3, arch_prctl, rseq
- Process lifecycle: brk, wait4, waitid
- Resource management: prlimit64, madvise
- I/O multiplexing: epoll_create1, epoll_ctl, epoll_wait, epoll_pwait, ppoll, pselect6

### sendfile / copy_file_range
- behavior: return ENOSYS to force read/write fallback
- rationale: these operate on FD pairs; virtual FDs cannot be passed to host kernel

---

## Legacy x86_64 (aarch64 uses *at variants)

stat, lstat, access, mkdir, rmdir, unlink, rename, chmod, chown, open:
all map to their *at equivalents with AT_FDCWD.

---

## Execution

### execve/execveat
- behavior: CONTINUE (host kernel handles; image-mode memfd extraction is MVP-deferred)
- return: does not return on success; -1 on failure

---

## Deviations from Rust Implementation

1. Partial write handling: C version correctly returns partial byte count per POSIX; Rust version returned error on mid-transfer failure.
2. dup2/dup3 atomicity: C version dups first, then closes old; Rust had the operations reversed.
3. fcntl F_DUPFD_CLOEXEC: C version tracks cloexec flag; Rust did not.
4. getresuid/getresgid: C version checks for negative return (error) before casting; Rust cast directly.
5. getgroups probe: C version uses getgroups(0, NULL); Rust called getgroups(size, NULL) which fails for size > 0.
6. setgroups: C version caps at NGROUPS_MAX; Rust allowed overflow.
7. connect: C version caps sockaddr at 4096 bytes; Rust used uncapped malloc.
