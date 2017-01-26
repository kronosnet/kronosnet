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
#if defined (IP_RECVERR) || defined (IPV6_RECVERR)
#include <linux/errqueue.h>
#endif

#include "libknet.h"
#include "compat.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "common.h"
#include "transports.h"
#include "threads_common.h"

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

static int udp_transport_link_set_config(knet_handle_t knet_h, struct knet_link *kn_link)
{
	int err = 0, savederrno = 0;
	int sock = -1;
	struct epoll_event ev;
	udp_link_info_t *info;
	udp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_UDP];
#if defined (IP_RECVERR) || defined (IPV6_RECVERR)
	int value;
#endif

	/*
	 * Only allocate a new link if the local address is different
	 */
	knet_list_for_each_entry(info, &handle_info->links_list, list) {
		if (memcmp(&info->local_address, &kn_link->src_addr, sizeof(struct sockaddr_storage)) == 0) {
			log_debug(knet_h, KNET_SUB_TRANSP_UDP, "Re-using existing UDP socket for new link");
			kn_link->outsock = info->socket_fd;
			kn_link->transport_link = info;
			kn_link->transport_connected = 1;
			return 0;
		}
	}

	info = malloc(sizeof(udp_link_info_t));
	if (!info) {
		err = -1;
		goto exit_error;
	}

	sock = socket(kn_link->src_addr.ss_family, SOCK_DGRAM, 0);
	if (sock < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_LISTENER, "Unable to create listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_configure_transport_socket(knet_h, sock, &kn_link->src_addr, "UDP") < 0) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

#ifdef IP_RECVERR
	if (kn_link->src_addr.ss_family == AF_INET) {
		value = 1;
		if (setsockopt(sock, SOL_IP, IP_RECVERR, &value, sizeof(value)) <0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSP_UDP, "Unable to set RECVERR on socket: %s",
				strerror(savederrno));
			goto exit_error;
		}
	}
#endif
#ifdef IPV6_RECVERR
	if (kn_link->src_addr.ss_family == AF_INET6) {
		value = 1;
		if (setsockopt(sock, SOL_IPV6, IPV6_RECVERR, &value, sizeof(value)) <0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSP_UDP, "Unable to set RECVERR on socket: %s",
				strerror(savederrno));
			goto exit_error;
		}
	}
#endif

	if (bind(sock, (struct sockaddr *)&kn_link->src_addr, sockaddr_len(&kn_link->src_addr))) {
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

	memcpy(&info->local_address, &kn_link->src_addr, sizeof(struct sockaddr_storage));
	info->socket_fd = sock;
	knet_list_add(&info->list, &handle_info->links_list);

	kn_link->outsock = sock;
	kn_link->transport_link = info;
	kn_link->transport_connected = 1;

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

static int udp_transport_link_clear_config(knet_handle_t knet_h, struct knet_link *kn_link)
{
	int err = 0, savederrno = 0;
	int found = 0;
	struct knet_host *host;
	int link_idx;
	udp_link_info_t *info = kn_link->transport_link;
	struct epoll_event ev;

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
			if (&host->link[link_idx] == kn_link)
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
	free(kn_link->transport_link);

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

#if defined (IP_RECVERR) || defined (IPV6_RECVERR)
static int read_errs_from_sock(knet_handle_t knet_h, int sockfd)
{
	int err = 0, savederrno = 0;
	int got_err = 0;
	char buffer[1024];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct sock_extended_err *sock_err;
	struct icmphdr icmph;
	struct sockaddr_storage remote;
	struct sockaddr_storage *origin;
	char addr_str[KNET_MAX_HOST_LEN];
	char port_str[KNET_MAX_PORT_LEN];

	iov.iov_base = &icmph;
	iov.iov_len = sizeof(icmph);
	msg.msg_name = (void*)&remote;
	msg.msg_namelen = sizeof(remote);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = buffer;
	msg.msg_controllen = sizeof(buffer);

	for (;;) {
		err = recvmsg(sockfd, &msg, MSG_ERRQUEUE);
		savederrno = errno;
		if (err < 0) {
			if (!got_err) {
				errno = savederrno;
				return -1;
			} else {
				return 0;
			}
		}
		got_err = 1;
		for (cmsg = CMSG_FIRSTHDR(&msg);cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (((cmsg->cmsg_level == SOL_IP) && (cmsg->cmsg_type == IP_RECVERR)) ||
			    ((cmsg->cmsg_level == SOL_IPV6 && (cmsg->cmsg_type == IPV6_RECVERR)))) {
				sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);
				if (sock_err) {
					switch (sock_err->ee_origin) {
						case 0: /* no origin */
						case 1: /* local source (EMSGSIZE) */
							/*
							 * those errors are way too noisy
							 */
							break;
						case 2: /* ICMP */
						case 3: /* ICMP6 */
							origin = (struct sockaddr_storage *)SO_EE_OFFENDER(sock_err);
							if (knet_addrtostr(origin, sizeof(origin),
									   addr_str, KNET_MAX_HOST_LEN,
									   port_str, KNET_MAX_PORT_LEN) < 0) {
								log_debug(knet_h, KNET_SUB_TRANSP_UDP, "Received ICMP error from unknown source: %s", strerror(sock_err->ee_errno));

							} else {
								log_debug(knet_h, KNET_SUB_TRANSP_UDP, "Received ICMP error from %s: %s", addr_str, strerror(sock_err->ee_errno));
							}
							break;
					}
				} else {
					log_debug(knet_h, KNET_SUB_TRANSP_UDP, "No data in MSG_ERRQUEUE");
				}
			}
		}
	}
}
#else
static int read_errs_from_sock(knet_handle_t knet_h, int sockfd)
{
	return 0;
}
#endif

static int udp_transport_rx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno)
{
	if (recv_errno == EAGAIN) {
		read_errs_from_sock(knet_h, sockfd);
	}
	return 0;
}

static int udp_transport_tx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno)
{
	if (recv_err < 0) {
		if ((recv_errno == ENOBUFS) || (recv_errno == EAGAIN)) {
			log_debug(knet_h, KNET_SUB_TRANSP_UDP, "Sock: %d is overloaded. Slowing TX down", sockfd);
			usleep(KNET_THREADS_TIMERES * 4);
			return 1;
		}
		read_errs_from_sock(knet_h, sockfd);
		if (recv_errno == EMSGSIZE) {
			return 0;
		}
		return -1;
	}

	return 0;
}

static int udp_transport_rx_is_data(knet_handle_t knet_h, int sockfd, struct mmsghdr *msg)
{
	if (msg->msg_len == 0)
		return 0;

	return 2;
}

static int udp_transport_link_dyn_connect(knet_handle_t knet_h, int sockfd, struct knet_link *kn_link)
{
	kn_link->status.dynconnected = 1;
	return 0;
}

static knet_transport_ops_t udp_transport_ops = {
	.transport_name = "UDP",
	.transport_id = KNET_TRANSPORT_UDP,
	.transport_mtu_overhead = KNET_PMTUD_UDP_OVERHEAD,
	.transport_init = udp_transport_init,
	.transport_free = udp_transport_free,
	.transport_link_set_config = udp_transport_link_set_config,
	.transport_link_clear_config = udp_transport_link_clear_config,
	.transport_link_dyn_connect = udp_transport_link_dyn_connect,
	.transport_rx_sock_error = udp_transport_rx_sock_error,
	.transport_tx_sock_error = udp_transport_tx_sock_error,
	.transport_rx_is_data = udp_transport_rx_is_data,
};

knet_transport_ops_t *get_udp_transport()
{
	return &udp_transport_ops;
}
