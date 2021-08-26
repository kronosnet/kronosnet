/*
 * Copyright (C) 2016-2021 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_TRANSPORTS_H__
#define __KNET_TRANSPORTS_H__

#define KNET_TRANSPORT_RX_ERROR -1
#define KNET_TRANSPORT_RX_NOT_DATA_CONTINUE 0
#define KNET_TRANSPORT_RX_NOT_DATA_STOP 1
#define KNET_TRANSPORT_RX_IS_DATA 2
#define KNET_TRANSPORT_RX_OOB_DATA_CONTINUE 3
#define KNET_TRANSPORT_RX_OOB_DATA_STOP 4

int start_all_transports(knet_handle_t knet_h);
void stop_all_transports(knet_handle_t knet_h);

int transport_link_set_config(knet_handle_t knet_h, struct knet_link *kn_link, uint8_t transport);
int transport_link_clear_config(knet_handle_t knet_h, struct knet_link *kn_link);
int transport_link_dyn_connect(knet_handle_t knet_h, int sockfd, struct knet_link *kn_link);
int transport_rx_sock_error(knet_handle_t knet_h, uint8_t transport, int sockfd, int recv_err, int recv_errno);
int transport_tx_sock_error(knet_handle_t knet_h, uint8_t transport, int sockfd, int recv_err, int recv_errno);
int transport_rx_is_data(knet_handle_t knet_h, uint8_t transport, int sockfd, struct knet_mmsghdr *msg);
int transport_get_proto(knet_handle_t knet_h, uint8_t transport);
int transport_get_acl_type(knet_handle_t knet_h, uint8_t transport);
int transport_get_connection_oriented(knet_handle_t knet_h, uint8_t transport);
int transport_link_is_down(knet_handle_t knet_h, struct knet_link *link);

#endif
