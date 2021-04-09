/*
 * Copyright (C) 2017-2021 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "libknet.h"
#include "compat.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "common.h"
#include "transports.h"
#include "transport_loopback.h"
#include "threads_common.h"

/* This is just a file of empty calls as the actual loopback is in threads_tx.c as a special case
   when receiving a packet from the localhost */


int loopback_transport_link_set_config(knet_handle_t knet_h, struct knet_link *kn_link)
{
	kn_link->transport_connected = 1;
	kn_link->status.connected = 1;
	return 0;
}

int loopback_transport_link_clear_config(knet_handle_t knet_h, struct knet_link *kn_link)
{
	return 0;
}

int loopback_transport_free(knet_handle_t knet_h)
{
	return 0;
}

int loopback_transport_init(knet_handle_t knet_h)
{
	return 0;
}

int loopback_transport_rx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno)
{
	return 0;
}

int loopback_transport_tx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno)
{
	return 0;
}

int loopback_transport_rx_is_data(knet_handle_t knet_h, int sockfd, struct knet_mmsghdr *msg)
{
	return 0;
}

int loopback_transport_link_dyn_connect(knet_handle_t knet_h, int sockfd, struct knet_link *kn_link)
{
	return 0;
}

int loopback_transport_link_get_acl_fd(knet_handle_t knet_h, struct knet_link *kn_link)
{
	return 0;
}

int loopback_transport_link_is_down(knet_handle_t knet_h, struct knet_link *kn_link)
{
	return 0;
}
