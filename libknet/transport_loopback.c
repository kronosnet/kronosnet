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
#include "threads_common.h"

#define KNET_PMTUD_LOOPBACK_OVERHEAD 0

/* This is just a file of empty calls as the actual loopback is in threads_tx.c as a special case
   when receiving a packet from the localhost */


static int loopback_transport_link_set_config(knet_handle_t knet_h, struct knet_link *kn_link)
{
	return 0;
}

static int loopback_transport_link_clear_config(knet_handle_t knet_h, struct knet_link *kn_link)
{
	return 0;
}

static int loopback_transport_free(knet_handle_t knet_h)
{
	return 0;
}

static int loopback_transport_init(knet_handle_t knet_h)
{
	return 0;
}

static int loopback_transport_rx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno)
{
	return 0;
}

static int loopback_transport_tx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno)
{
	return 0;
}

static int loopback_transport_rx_is_data(knet_handle_t knet_h, int sockfd, struct knet_mmsghdr *msg)
{
	return 0;
}

static int loopback_transport_link_dyn_connect(knet_handle_t knet_h, int sockfd, struct knet_link *kn_link)
{
	return 0;
}

static knet_transport_ops_t loopback_transport_ops = {
	.transport_name = "LOOPBACK",
	.transport_id = KNET_TRANSPORT_LOOPBACK,
	.transport_mtu_overhead = 0,
	.transport_init = loopback_transport_init,
	.transport_free = loopback_transport_free,
	.transport_link_set_config = loopback_transport_link_set_config,
	.transport_link_clear_config = loopback_transport_link_clear_config,
	.transport_link_dyn_connect = loopback_transport_link_dyn_connect,
	.transport_rx_sock_error = loopback_transport_rx_sock_error,
	.transport_tx_sock_error = loopback_transport_tx_sock_error,
	.transport_rx_is_data = loopback_transport_rx_is_data,
};

knet_transport_ops_t *get_loopback_transport()
{
	return &loopback_transport_ops;
}
