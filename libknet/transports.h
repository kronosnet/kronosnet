/*
 * Copyright (C) 2016-2025 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_TRANSPORTS_H__
#define __KNET_TRANSPORTS_H__

int start_all_transports(knet_handle_t knet_h);
void stop_all_transports(knet_handle_t knet_h);

int transport_link_set_config(knet_handle_t knet_h, struct knet_link *kn_link, uint8_t transport);
int transport_link_clear_config(knet_handle_t knet_h, struct knet_link *kn_link);
int transport_link_dyn_connect(knet_handle_t knet_h, int sockfd, struct knet_link *kn_link);
int transport_rx_sock_error(knet_handle_t knet_h, uint8_t transport, int sockfd, int recv_err, int recv_errno);
int transport_tx_sock_error(knet_handle_t knet_h, uint8_t transport, int sockfd, int subsys, int recv_err, int recv_errno);
int transport_rx_is_data(knet_handle_t knet_h, uint8_t transport, int sockfd, struct knet_mmsghdr *msg);
int transport_get_proto(knet_handle_t knet_h, uint8_t transport);
int transport_get_acl_type(knet_handle_t knet_h, uint8_t transport);
int transport_get_connection_oriented(knet_handle_t knet_h, uint8_t transport);
int transport_link_is_down(knet_handle_t knet_h, struct knet_link *link);

#endif
