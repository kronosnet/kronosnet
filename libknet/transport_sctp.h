/*
 * Copyright (C) 2017-2020 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include "internals.h"

#ifndef __KNET_TRANSPORT_SCTP_H__
#define __KNET_TRANSPORT_SCTP_H__

/*
 * https://en.wikipedia.org/wiki/SCTP_packet_structure
 */

#define KNET_PMTUD_SCTP_OVERHEAD_COMMON 12
#define KNET_PMTUD_SCTP_OVERHEAD_DATA_CHUNK 16
#define KNET_PMTUD_SCTP_OVERHEAD KNET_PMTUD_SCTP_OVERHEAD_COMMON + KNET_PMTUD_SCTP_OVERHEAD_DATA_CHUNK

#ifdef HAVE_NETINET_SCTP_H

int sctp_transport_link_set_config(knet_handle_t knet_h, struct knet_link *kn_link);
int sctp_transport_link_clear_config(knet_handle_t knet_h, struct knet_link *kn_link);
int sctp_transport_free(knet_handle_t knet_h);
int sctp_transport_init(knet_handle_t knet_h);
int sctp_transport_rx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno);
int sctp_transport_tx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno);
int sctp_transport_rx_is_data(knet_handle_t knet_h, int sockfd, struct knet_mmsghdr *msg);
int sctp_transport_link_dyn_connect(knet_handle_t knet_h, int sockfd, struct knet_link *kn_link);
int sctp_transport_link_get_acl_fd(knet_handle_t knet_h, struct knet_link *kn_link);
int sctp_transport_link_is_down(knet_handle_t knet_h, struct knet_link *kn_link);

#endif

#endif
