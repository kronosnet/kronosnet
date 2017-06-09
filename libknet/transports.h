/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNET_TRANSPORTS_H__
#define __KNET_TRANSPORTS_H__

knet_transport_ops_t *get_udp_transport(void);
knet_transport_ops_t *get_sctp_transport(void);

int _configure_common_socket(knet_handle_t knet_h, int sock, uint64_t flags, const char *type);
int _configure_transport_socket(knet_handle_t knet_h, int sock, struct sockaddr_storage *address, uint64_t flags, const char *type);

int _init_socketpair(knet_handle_t knet_h, int *sock);
void _close_socketpair(knet_handle_t knet_h, int *sock);

int _set_fd_tracker(knet_handle_t knet_h, int sockfd, uint8_t transport, uint8_t data_type, void *data);
int _is_valid_fd(knet_handle_t knet_h, int sockfd);

int _sendmmsg(int sockfd, struct knet_mmsghdr *msgvec, unsigned int vlen, unsigned int flags);
int _recvmmsg(int sockfd, struct knet_mmsghdr *msgvec, unsigned int vlen, unsigned int flags);

#endif
