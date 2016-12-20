#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <math.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <malloc.h>

#include "libknet.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "common.h"
#include "transports.h"

#define KNET_PMTUD_UDP_OVERHEAD 8

typedef struct udp_handle_info {
	knet_handle_t knet_h;
	struct knet_list_head links_list;
} udp_handle_info_t;

typedef struct udp_link_info {
	knet_transport_link_t transport;
	knet_handle_t knet_handle;
	int socket_fd;
	udp_handle_info_t *handle_info;
	struct knet_list_head list;
	struct sockaddr_storage local_address;
} udp_link_info_t;

static int udp_handle_allocate(knet_handle_t knet_h, knet_transport_t *transport)
{
	udp_handle_info_t * handle_info;

	handle_info = malloc(sizeof(udp_handle_info_t));
	if (!handle_info) {
		return -1;
	}
	handle_info->knet_h = knet_h;
	knet_list_init(&handle_info->links_list);

	*transport = handle_info;
	return 0;
}

static int udp_handle_free(knet_handle_t knet_h, knet_transport_t transport)
{
	free(transport);
	return 0;
}

static int udp_link_listener_start(knet_handle_t knet_h, knet_transport_link_t transport_link,
				   uint8_t link_id,
				   struct sockaddr_storage *address, struct sockaddr_storage *dst_address)
{
	return 0;
}


static int udp_link_allocate(knet_handle_t knet_h, knet_transport_t transport,
			     struct knet_link *link,
			     knet_transport_link_t *transport_link,
			     uint8_t link_id,
			     struct sockaddr_storage *address, struct sockaddr_storage *dst_address,
			     int *send_sock)
{
	int sock;
	int savederrno;
	struct epoll_event ev;
	int err;
	udp_link_info_t *info;
	udp_handle_info_t *handle_info = transport;

	/* Only allocate a new link if the local address is different */
	knet_list_for_each_entry(info, &handle_info->links_list, list) {
		if (memcmp(&info->local_address, address, sizeof(struct sockaddr_storage)) == 0) {

			log_debug(knet_h, KNET_SUB_TRANSP_UDP, "Re-using existing UDP socket for new link");
			*send_sock = info->socket_fd;
			*transport_link = info;
			return 0;
		}
	}

	info = malloc(sizeof(udp_link_info_t));
	if (!info) {
		return -1;
	}
	info->knet_handle = knet_h;
	info->handle_info = handle_info;

	sock = socket(address->ss_family, SOCK_DGRAM, 0);
	if (sock < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_LISTENER, "Unable to create listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_configure_transport_socket(knet_h, sock, dst_address, "UDP") < 0) {
		err = -1;
		goto exit_error;
	}

	if (bind(sock, (struct sockaddr *)address, sizeof(struct sockaddr_storage)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_UDP, "Unable to bind listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = sock;

	if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_ADD, sock, &ev)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_UDP, "Unable to add listener to epoll pool: %s",
			strerror(savederrno));
		goto exit_error;
	}

	memcpy(&info->local_address, address, sizeof(struct sockaddr_storage));
	knet_list_add(&info->list, &handle_info->links_list);
	info->socket_fd = sock;
	*transport_link = &info->transport;
	*send_sock = sock;
	return 0;

exit_error:
	return err;
}

static int udp_link_free(knet_transport_link_t transport)
{
	udp_link_info_t *info = transport;
	udp_handle_info_t *handle_info = info->handle_info;

	knet_list_del(&info->list);

	if (knet_list_empty(&handle_info->links_list)) {
		free(transport);
	}
	return 0;
}

static int udp_link_get_mtu_overhead(knet_transport_link_t transport)
{
	return KNET_PMTUD_UDP_OVERHEAD;
}

static knet_transport_ops_t udp_transport_ops = {
	.handle_allocate = udp_handle_allocate,
	.handle_free = udp_handle_free,

	.link_allocate = udp_link_allocate,
	.link_listener_start = udp_link_listener_start,
	.link_free = udp_link_free,
	.link_get_mtu_overhead = udp_link_get_mtu_overhead,
	.transport_name = "UDP",
};

knet_transport_ops_t *get_udp_transport()
{
	return &udp_transport_ops;
}
