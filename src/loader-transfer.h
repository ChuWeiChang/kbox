/* SPDX-License-Identifier: MIT */
#ifndef KBOX_LOADER_TRANSFER_H
#define KBOX_LOADER_TRANSFER_H

#include <stdint.h>

#include "loader-handoff.h"

struct kbox_loader_transfer_state {
    enum kbox_loader_entry_arch arch;
    uint64_t pc;
    uint64_t sp;
    uint64_t regs[6];
    uint64_t entry_map_start;
    uint64_t entry_map_end;
    uint64_t stack_map_start;
    uint64_t stack_map_end;
};

int kbox_loader_prepare_transfer(const struct kbox_loader_handoff *handoff,
                                 struct kbox_loader_transfer_state *state);
__attribute__((noreturn)) void kbox_loader_transfer_to_guest(
    const struct kbox_loader_transfer_state *state);

#endif /* KBOX_LOADER_TRANSFER_H */
