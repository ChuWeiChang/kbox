/* SPDX-License-Identifier: MIT */

#ifndef KBOX_NET_H
#define KBOX_NET_H

struct kbox_sysnrs;

int kbox_net_add_device(void);
int kbox_net_configure(const struct kbox_sysnrs *sysnrs);
void kbox_net_cleanup(void);
int kbox_net_is_active(void);
int kbox_net_register_socket(int lkl_fd, int supervisor_fd, int sock_type);
void kbox_net_deregister_socket(int lkl_fd);

#endif /* KBOX_NET_H */
