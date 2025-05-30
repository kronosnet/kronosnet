/*
 * Copyright (C) 2017-2025 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include "internals.h"

#ifndef __KNET_TRANSPORT_LOOPBACK_H__
#define __KNET_TRANSPORT_LOOPBACK_H__

#define KNET_PMTUD_LOOPBACK_OVERHEAD 0

int loopback_transport_link_set_config(knet_handle_t knet_h, struct knet_link *kn_link);
int loopback_transport_link_clear_config(knet_handle_t knet_h, struct knet_link *kn_link);
int loopback_transport_free(knet_handle_t knet_h);
int loopback_transport_init(knet_handle_t knet_h);
transport_sock_error_t loopback_transport_rx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno);
transport_sock_error_t loopback_transport_tx_sock_error(knet_handle_t knet_h, int sockfd, int subsys, int recv_err, int recv_errno);
transport_rx_isdata_t loopback_transport_rx_is_data(knet_handle_t knet_h, int sockfd, struct knet_mmsghdr *msg);
int loopback_transport_link_dyn_connect(knet_handle_t knet_h, int sockfd, struct knet_link *kn_link);
int loopback_transport_link_is_down(knet_handle_t knet_h, struct knet_link *kn_link);

#endif
