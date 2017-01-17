#include "config.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>

#include "libknet.h"
#include "compat.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "common.h"
#include "transports.h"

#define KNET_PMTUD_UDP_OVERHEAD 8

typedef struct udp_handle_info {
	struct knet_list_head links_list;
} udp_handle_info_t;

typedef struct udp_link_info {
	struct knet_list_head list;
	struct sockaddr_storage local_address;
	int socket_fd;
	int on_epoll;
} udp_link_info_t;

static int udp_transport_link_set_config(knet_handle_t knet_h, struct knet_link *link)
{
	int err = 0, savederrno = 0;
	int sock = -1;
	struct epoll_event ev;
	udp_link_info_t *info;
	udp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_UDP];

	/*
	 * Only allocate a new link if the local address is different
	 */
	knet_list_for_each_entry(info, &handle_info->links_list, list) {
		if (memcmp(&info->local_address, &link->src_addr, sizeof(struct sockaddr_storage)) == 0) {
			log_debug(knet_h, KNET_SUB_TRANSP_UDP, "Re-using existing UDP socket for new link");
			link->outsock = info->socket_fd;
			link->transport_link = info;
			link->transport_connected = 1;
			return 0;
		}
	}

	info = malloc(sizeof(udp_link_info_t));
	if (!info) {
		err = -1;
		goto exit_error;
	}

	sock = socket(link->src_addr.ss_family, SOCK_DGRAM, 0);
	if (sock < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_LISTENER, "Unable to create listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_configure_transport_socket(knet_h, sock, &link->src_addr, "UDP") < 0) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

	if (bind(sock, (struct sockaddr *)&link->src_addr, sockaddr_len(&link->src_addr))) {
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

	info->on_epoll = 1;

	if (_set_fd_tracker(knet_h, sock, KNET_TRANSPORT_UDP, 0, info) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_UDP, "Unable to set fd tracker: %s",
			strerror(savederrno));
		goto exit_error;
	}

	memcpy(&info->local_address, &link->src_addr, sizeof(struct sockaddr_storage));
	info->socket_fd = sock;
	knet_list_add(&info->list, &handle_info->links_list);

	link->outsock = sock;
	link->transport_link = info;
	link->transport_connected = 1;

exit_error:
	if (err) {
		if (info) {
			if (info->on_epoll) {
				epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, sock, &ev);
			}
			free(info);
		}
		if (sock >= 0) {
			close(sock);
		}
	}
	errno = savederrno;
	return err;
}

static int udp_transport_link_clear_config(knet_handle_t knet_h, struct knet_link *link)
{
	int err = 0, savederrno = 0;
	int found = 0;
	struct knet_host *host;
	int link_idx;
	udp_link_info_t *info = link->transport_link;
	struct epoll_event ev;

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
			if (&host->link[link_idx] == link)
				continue;

			if ((host->link[link_idx].transport_link == info) &&
			    (host->link[link_idx].status.enabled == 1)) {
				found = 1;
				break;
			}
		}
	}

	if (found) {
		log_debug(knet_h, KNET_SUB_TRANSP_UDP, "UDP socket %d still in use", info->socket_fd);
		savederrno = EBUSY;
		err = -1;
		goto exit_error;
	}

	if (info->on_epoll) {
		memset(&ev, 0, sizeof(struct epoll_event));
		ev.events = EPOLLIN;
		ev.data.fd = info->socket_fd;

		if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, info->socket_fd, &ev) < 0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSP_UDP, "Unable to remove UDP socket from epoll poll: %s",
				strerror(errno));
			goto exit_error;
		}
		info->on_epoll = 0;
	}

	if (_set_fd_tracker(knet_h, info->socket_fd, KNET_MAX_TRANSPORTS, 0, NULL) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_UDP, "Unable to set fd tracker: %s",
			strerror(savederrno));
		goto exit_error;
	}

	close(info->socket_fd);
	knet_list_del(&info->list);
	free(link->transport_link);

exit_error:
	errno = savederrno;
	return err;
}

static int udp_transport_free(knet_handle_t knet_h)
{
	udp_handle_info_t *handle_info;

	if (!knet_h->transports[KNET_TRANSPORT_UDP]) {
		errno = EINVAL;
		return -1;
	}

	handle_info = knet_h->transports[KNET_TRANSPORT_UDP];

	/*
	 * keep it here while we debug list usage and such
	 */
	if (!knet_list_empty(&handle_info->links_list)) {
		log_err(knet_h, KNET_SUB_TRANSP_UDP, "Internal error. handle list is not empty");
		return -1;
	}

	free(handle_info);

	knet_h->transports[KNET_TRANSPORT_UDP] = NULL;

	return 0;
}

static int udp_transport_init(knet_handle_t knet_h)
{
	udp_handle_info_t *handle_info;

	if (knet_h->transports[KNET_TRANSPORT_UDP]) {
		errno = EEXIST;
		return -1;
	}

	handle_info = malloc(sizeof(udp_handle_info_t));
	if (!handle_info) {
		return -1;
	}

	knet_h->transports[KNET_TRANSPORT_UDP] = handle_info;

	knet_list_init(&handle_info->links_list);

	return 0;
}

static int udp_transport_rx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno)
{
	/*
	 * UDP can't do much here afaict, perhaps clear the SO_ERROR?
	 */
	log_err(knet_h, KNET_SUB_TRANSP_UDP, "Sock: %d received error: %d (%s)",
		sockfd, recv_err, strerror(recv_errno));
	return 0;
}

static int udp_transport_rx_is_data(knet_handle_t knet_h, int sockfd, struct mmsghdr msg)
{
	if (msg.msg_len == 0)
		return 0;

	return 2;
}

static knet_transport_ops_t udp_transport_ops = {
	.transport_name = "UDP",
	.transport_mtu_overhead = KNET_PMTUD_UDP_OVERHEAD,
	.transport_init = udp_transport_init,
	.transport_free = udp_transport_free,
	.transport_link_set_config = udp_transport_link_set_config,
	.transport_link_clear_config = udp_transport_link_clear_config,
	.transport_rx_sock_error = udp_transport_rx_sock_error,
	.transport_rx_is_data = udp_transport_rx_is_data,
};

knet_transport_ops_t *get_udp_transport()
{
	return &udp_transport_ops;
}
