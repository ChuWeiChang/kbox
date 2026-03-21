/* SPDX-License-Identifier: MIT */
#ifndef KBOX_WEB_H
#define KBOX_WEB_H

#include <stdint.h>

enum kbox_syscall_family {
    KBOX_FAM_FILE_IO,
    KBOX_FAM_DIR,
    KBOX_FAM_FD_OPS,
    KBOX_FAM_IDENTITY,
    KBOX_FAM_MEMORY,
    KBOX_FAM_SIGNALS,
    KBOX_FAM_SCHEDULER,
    KBOX_FAM_OTHER,
    KBOX_FAM_COUNT,
};

enum kbox_disposition {
    KBOX_DISP_CONTINUE,
    KBOX_DISP_RETURN,
    KBOX_DISP_ENOSYS,
    KBOX_DISP_COUNT,
};

struct kbox_telemetry_counters {
    uint64_t syscall_total;
    uint64_t disp_continue;
    uint64_t disp_return;
    uint64_t disp_enosys;
    uint64_t family[KBOX_FAM_COUNT];
    uint64_t latency_total_ns;
    uint64_t latency_max_ns;
    uint64_t enosys_hits[1024];
    uint64_t enosys_overflow;
    int enosys_overflow_last_nr;
    uint64_t recv_enoent;
    uint64_t send_enoent;
    uint64_t vm_readv_efault;
    uint64_t vm_readv_esrch;
    uint64_t vm_readv_eperm;
    uint64_t vm_writev_efault;
    uint64_t vm_writev_esrch;
    uint64_t addfd_ok;
    uint64_t addfd_enoent;
    uint64_t addfd_ebadf;
    uint64_t addfd_emfile;
    uint64_t addfd_other_err;
};

#define KBOX_SNAPSHOT_VERSION 1

struct kbox_telemetry_snapshot {
    uint32_t version;
    uint64_t timestamp_ns;
    uint64_t uptime_ns;
    uint64_t context_switches;
    uint64_t softirqs[10];
    uint64_t softirq_total;
    uint64_t mem_total;
    uint64_t mem_free;
    uint64_t mem_available;
    uint64_t buffers;
    uint64_t cached;
    uint64_t slab;
    uint64_t pgfault;
    uint64_t pgmajfault;
    uint32_t loadavg_1;
    uint32_t loadavg_5;
    uint32_t loadavg_15;
    uint32_t fd_table_used;
    uint32_t fd_table_max;
    struct kbox_telemetry_counters counters;
};

#define KBOX_EVENT_RING_SIZE 1024
#define KBOX_EVENT_RING_ROUTINE 768
#define KBOX_EVENT_RING_ERROR 256

enum kbox_event_type {
    KBOX_EVT_SYSCALL,
};

struct kbox_syscall_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    int syscall_nr;
    const char *syscall_name;
    uint64_t args[6];
    enum kbox_disposition disposition;
    int64_t return_value;
    int error_nr;
    uint64_t latency_ns;
};

struct kbox_event {
    enum kbox_event_type type;
    uint64_t seq;
    union {
        struct kbox_syscall_event syscall;
    };
};

struct kbox_event_ring {
    struct kbox_event entries[KBOX_EVENT_RING_SIZE];
    uint64_t write_seq;
    int routine_head;
    int error_head;
};

struct kbox_web_ctx;
struct kbox_sysnrs;

void kbox_event_ring_init(struct kbox_event_ring *ring);
void kbox_event_push_syscall(struct kbox_event_ring *ring,
                             uint32_t *rng_state,
                             int sample_pct,
                             const struct kbox_syscall_event *evt);
int kbox_event_to_json(const struct kbox_event *evt, char *buf, int bufsz);
uint64_t kbox_event_ring_iterate(const struct kbox_event_ring *ring,
                                 uint64_t from_seq,
                                 void (*cb)(const struct kbox_event *evt,
                                            void *userdata),
                                 void *userdata);
void kbox_telemetry_sample(const struct kbox_sysnrs *s,
                           struct kbox_telemetry_snapshot *snap,
                           uint64_t boot_time_ns,
                           uint32_t fd_used,
                           uint32_t fd_max,
                           const struct kbox_telemetry_counters *counters);
int kbox_snapshot_to_json(const struct kbox_telemetry_snapshot *snap,
                          char *buf,
                          int bufsz);
int kbox_stats_to_json(const struct kbox_telemetry_snapshot *snap,
                       const char *guest_name,
                       char *buf,
                       int bufsz);
int kbox_enosys_to_json(const struct kbox_telemetry_counters *c,
                        char *buf,
                        int bufsz);

struct kbox_web_config {
    int port;
    const char *bind;
    int sample_ms;
    int enable_web;
    int enable_trace;
    int trace_fd;
    const char *guest_name;
};

struct kbox_web_ctx *kbox_web_init(const struct kbox_web_config *cfg,
                                   const struct kbox_sysnrs *sysnrs);
void kbox_web_shutdown(struct kbox_web_ctx *ctx);
void kbox_web_tick(struct kbox_web_ctx *ctx);
void kbox_web_record_syscall(struct kbox_web_ctx *ctx,
                             uint32_t pid,
                             int syscall_nr,
                             const char *syscall_name,
                             const uint64_t args[6],
                             enum kbox_disposition disp,
                             int64_t ret_val,
                             int error_nr,
                             uint64_t latency_ns);
struct kbox_telemetry_counters *kbox_web_counters(struct kbox_web_ctx *ctx);
void kbox_web_set_fd_used(struct kbox_web_ctx *ctx, uint32_t n);
uint64_t kbox_clock_ns(void);

#endif /* KBOX_WEB_H */
