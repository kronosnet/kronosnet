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
#include <qb/qblist.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "libknet.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "common.h"
#include "transports.h"

/*
 * https://en.wikipedia.org/wiki/Transmission_Control_Protocol
 */
#define KNET_PMTUD_TCP_OVERHEAD 20

/* Time to sleep before reconnection attempts. in microseconds */
#define KNET_TCP_SLEEP_TIME 1000000

#define MAX_ACCEPTED_SOCKS 256
typedef struct tcp_handle_info {
	knet_handle_t knet_handle;
	int connect_epollfd;
	int listen_epollfd;
	pthread_t connect_thread;
	pthread_t listen_thread;
	struct qb_list_head links_list;
} tcp_handle_info_t;

typedef struct tcp_link_info {
	knet_transport_t transport;
	knet_handle_t knet_handle;
	struct knet_link *link;
	int sendrecv_sock;
	int listen_sock;
	int accepted_socks[MAX_ACCEPTED_SOCKS];
	struct sockaddr_storage dst_address;
	struct qb_list_head list;
	int on_epoll;
} tcp_link_info_t;


static int _configure_tcp_socket(knet_handle_t knet_h, int sock, struct sockaddr_storage *address, const char *type)
{
	int err = 0;
	int value;
	int savederrno;

	if (_configure_transport_socket(knet_h, sock, address, type) < 0) {
		err = -1;
		goto exit_error;
	}

	value = 1;
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to set tcp nodelay: %s",
			strerror(savederrno));
		goto exit_error;
	}

	err = 0;

exit_error:
	return err;
}

/* Listener received a new connection */
static void _handle_incoming_tcp(tcp_handle_info_t *handle_info, int fd)
{
	tcp_link_info_t *info;
	knet_handle_t knet_h = handle_info->knet_handle;
	int new_fd;
	int err;
	int i;
	struct epoll_event ev;
	struct sockaddr_storage ss;
	socklen_t sock_len = sizeof(ss);

	new_fd = accept(fd, (struct sockaddr *)&ss, &sock_len);
	if (new_fd < 0) {
		log_warn(knet_h, KNET_SUB_TCP_LINK_T, "TCP handler ACCEPT ERROR: %s", strerror(errno));
		return;
	}

	err = _fdset_cloexec(new_fd);
	if (err) {
		log_debug(knet_h, KNET_SUB_TCP_LINK_T, "TCP handler thread INCOMING unable to set socket opts: %s", strerror(errno));
		return;
	}

	/* Find the link associated with this fd */
	qb_list_for_each_entry(info, &handle_info->links_list, list) {
		if (fd == info->listen_sock) {
			/* Keep a track of all accepted FDs */
			for (i=0; i<MAX_ACCEPTED_SOCKS; i++) {
				if (info->accepted_socks[i] == -1) {
					info->accepted_socks[i] = new_fd;
					break;
				}
			}

			memset(&ev, 0, sizeof(struct epoll_event));
			ev.events = EPOLLIN;
			ev.data.fd = new_fd;
			if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_ADD, new_fd, &ev)) {
				log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to add accepted socket %d to epoll pool: %s",
					new_fd, strerror(errno));
				close(new_fd);
			}
			else {
				log_debug(knet_h, KNET_SUB_TCP_LINK_T, "TCP handler ACCEPTED new fd %d for %s (listen fd: %d). index: %d", new_fd, _transport_print_ip(&ss), fd, i);
			}
			break;
		}
	}
}
static int _create_connect_socket(knet_handle_t knet_h, tcp_handle_info_t *handle_info,
				  tcp_link_info_t *info, int do_close)
{
	int sendrecv_sock;
	int savederrno = EINVAL;
	struct epoll_event ev;

	memset(&ev, 0, sizeof(struct epoll_event));
	if (do_close || info->sendrecv_sock != -1) {

		if (info->on_epoll) {
			ev.events = EPOLLOUT;
			ev.data.fd = info->sendrecv_sock;
			if (epoll_ctl(handle_info->connect_epollfd, EPOLL_CTL_DEL, info->sendrecv_sock, &ev)) {
				log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to remove connected socket from epoll pool: %s",
					strerror(errno));
			}
		}

		close(info->sendrecv_sock);
		info->on_epoll = 0;

		sendrecv_sock = socket(info->dst_address.ss_family, SOCK_STREAM, IPPROTO_TCP);
		if (sendrecv_sock < 0) {
			savederrno = errno;
			sendrecv_sock = -1;
			log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to create send/recv socket: %s",
				strerror(savederrno));
			goto exit_error;
		}

		if (_configure_tcp_socket(knet_h, sendrecv_sock, &info->dst_address, "send/recv") < 0) {
			/* Error already reported */
			goto exit_error;
		}
	}
	else {
		sendrecv_sock = info->sendrecv_sock;
	}

	if (connect(sendrecv_sock, (struct sockaddr *)&info->dst_address, sizeof(struct sockaddr_storage)) < 0) {
		if (errno != EINPROGRESS && errno != EISCONN) {
			savederrno = errno;
			sendrecv_sock = -1;
			log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to connect TCP socket: %s",
				strerror(savederrno));
			goto exit_error;
		}
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLOUT;
	ev.data.fd = sendrecv_sock;
	if (epoll_ctl(handle_info->connect_epollfd, EPOLL_CTL_ADD, sendrecv_sock, &ev)) {
		savederrno = errno;
		sendrecv_sock = -1;
		log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to add send/recv to epoll pool: %s",
			strerror(savederrno));
		goto exit_error;
	}

	log_debug(knet_h, KNET_SUB_TCP_LINK_T, "New connect attempt to %s on fd %d", _transport_print_ip(&info->dst_address), sendrecv_sock);

	info->sendrecv_sock = sendrecv_sock;
exit_error:
	return sendrecv_sock;
}

/* Connect completed or failed */
static void _handle_connected_tcp(tcp_handle_info_t *handle_info, int fd)
{
	knet_handle_t knet_h = handle_info->knet_handle;
	tcp_link_info_t *info;
	struct epoll_event ev;
	int err;
	unsigned int status, len = sizeof(status);

	/* Find the link associated with this fd */
	qb_list_for_each_entry(info, &handle_info->links_list, list) {
		if (fd == info->sendrecv_sock) {

			err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &status, &len);
			if (err || status) {

				if (err) {
					log_err(knet_h, KNET_SUB_TCP_LINK_T, "TCP getsockopt() on connecting socket %d failed: %s",
						fd, strerror(errno));
				}
				else {
					log_err(knet_h, KNET_SUB_TCP_LINK_T, "TCP connect on %d to %s failed: %s",
						fd, _transport_print_ip(&info->dst_address),
						strerror(status));

					/* Retry connect */
					usleep(KNET_TCP_SLEEP_TIME);

					/* No need to create a new socket if connect failed,
					 * just retry connect
					 */
					info->sendrecv_sock = _create_connect_socket(knet_h, handle_info, info, 0);
				}
				return;
			}

			/* Connected - Remove us from the connect epoll */
			ev.events = EPOLLOUT;
			ev.data.fd = fd;
			if (epoll_ctl(handle_info->connect_epollfd, EPOLL_CTL_DEL, fd, &ev)) {
				log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to remove connected socket from epoll pool: %s",
					strerror(errno));
			}

			/* Add this FD to the main read epoll */
			if (!info->on_epoll) {
				ev.events = EPOLLIN;
				ev.data.fd = fd;
				if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_ADD, fd, &ev)) {
					log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to add connected socket to epoll pool: %s",
						strerror(errno));
				}
				else {
					info->on_epoll = 1;
				}
			}
			log_debug(knet_h, KNET_SUB_TCP_LINK_T, "TCP handler fd %d now connected to %s", fd,
				  _transport_print_ip(&info->dst_address));

			break;
		}
	}
}

static void *_tcp_listen_thread(void *data)
{
	int i, nev;
	tcp_handle_info_t *handle_info = (tcp_handle_info_t*) data;
	knet_handle_t knet_h = handle_info->knet_handle;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];

	while (!knet_h->fini_in_progress) {
		nev = epoll_wait(handle_info->listen_epollfd, events, KNET_EPOLL_MAX_EVENTS, -1);

		if (knet_h->fini_in_progress) {
			break;
		}

		if (nev < 0) {
			log_debug(knet_h, KNET_SUB_TCP_LINK_T, "TCP listen handler EPOLL ERROR: %s", strerror(errno));
			continue;
		}

		/* Sort out which FD has an incoming connection */
		for (i = 0; i < nev; i++) {
			_handle_incoming_tcp(handle_info, events[i].data.fd);
		}
	}
	return NULL;
}


static void *_tcp_connect_thread(void *data)
{
	int i, nev;
	tcp_handle_info_t *handle_info = (tcp_handle_info_t*) data;
	knet_handle_t knet_h = handle_info->knet_handle;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];

	while (!knet_h->fini_in_progress) {
		nev = epoll_wait(handle_info->connect_epollfd, events, KNET_EPOLL_MAX_EVENTS, -1);

		if (knet_h->fini_in_progress) {
			break;
		}

		if (nev < 0) {
			log_debug(knet_h, KNET_SUB_TCP_LINK_T, "TCP connect handler EPOLL ERROR: %s", strerror(errno));
			continue;
		}

		/* Sort out which FD has a connection */
		for (i = 0; i < nev; i++) {
			_handle_connected_tcp(handle_info, events[i].data.fd);
		}
	}
	return NULL;
}

/*
 * EOF on the socket, find the link and set it waiting for connect() again
 * Returns -1 if the fd is not known to us
 */
static int tcp_handle_fd_eof(knet_handle_t knet_h, int sock_fd)
{
	tcp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_TCP];
	tcp_link_info_t *info;
	int ret = -1;
	int i;

	/* Not us */
	if (!handle_info) {
		return ret;
	}

	qb_list_for_each_entry(info, &handle_info->links_list, list) {
		if (sock_fd == info->sendrecv_sock) {

			log_info(knet_h, KNET_SUB_TCP_LINK_T, "Restarting connect for closed socket %d", sock_fd);

			/* Restart the connect() attempts */
			info->sendrecv_sock = _create_connect_socket(knet_h, handle_info, info, 1);
			info->link->outsock = info->sendrecv_sock;

			return 0;
		}

		/* Accepted socket - remove it from the epoll & close it */
		for (i=0; i<MAX_ACCEPTED_SOCKS; i++) {
			if (sock_fd == info->accepted_socks[i]) {
				struct epoll_event ev;

				memset(&ev, 0, sizeof(struct epoll_event));
				ev.events = EPOLLIN;
				ev.data.fd = sock_fd;

				log_info(knet_h, KNET_SUB_TCP_LINK_T, "Closing accepted socket %d", sock_fd);

				if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, sock_fd, &ev)) {
					log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to remove accepted socket %d to epoll pool: %s",
						sock_fd, strerror(errno));
				}
				close(sock_fd);
				info->accepted_socks[i] = -1;
				return 0;
			}
		}
	}

	log_info(knet_h, KNET_SUB_TCP_LINK_T, "Cannot find link_info for EOF socket %d", sock_fd);
	return -1;
}

static int tcp_handle_allocate(knet_handle_t knet_h, knet_transport_t *transport)
{
	tcp_handle_info_t *handle_info;
	int savederrno;

	handle_info = malloc(sizeof(tcp_handle_info_t));
	if (!handle_info) {
		return -1;
	}
	handle_info->knet_handle = knet_h;
	qb_list_init(&handle_info->links_list);

	handle_info->listen_epollfd = epoll_create(KNET_EPOLL_MAX_EVENTS + 1);
        if (handle_info->listen_epollfd < 0) {
                savederrno = errno;
                log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to create epoll listen fd: %s",
                        strerror(savederrno));
                goto exit_fail;
        }

	handle_info->connect_epollfd = epoll_create(KNET_EPOLL_MAX_EVENTS + 1);
        if (handle_info->connect_epollfd < 0) {
                savederrno = errno;
                log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to create epoll connect fd: %s",
                        strerror(savederrno));
                goto exit_fail;
        }

	/* Start connect & listener threads */

	savederrno = pthread_create(&handle_info->listen_thread, NULL, _tcp_listen_thread, handle_info);
        if (savederrno) {
                log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to start tcp listen thread: %s",
                        strerror(savederrno));
                goto exit_fail;
        }

	savederrno = pthread_create(&handle_info->connect_thread, NULL, _tcp_connect_thread, handle_info);
        if (savederrno) {
                log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to start tcp connect thread: %s",
                        strerror(savederrno));
                goto exit_fail;
        }

	*transport = handle_info;

	return 0;

exit_fail:
	errno = savederrno;
	return -1;
}

static int tcp_handle_free(knet_handle_t knet_h, knet_transport_t transport)
{
	tcp_handle_info_t *handle_info;
	void *thread_status;

	if (!transport) {
		errno = EINVAL;
		return -1;
	}

	handle_info = transport;

	if (handle_info->listen_thread) {
		pthread_cancel(handle_info->listen_thread);
		pthread_join(handle_info->listen_thread, &thread_status);
	}

	if (handle_info->connect_thread) {
		pthread_cancel(handle_info->connect_thread);
		pthread_join(handle_info->connect_thread, &thread_status);
	}

	free(handle_info);

	return 0;
}


static int tcp_link_listener_start(knet_handle_t knet_h, knet_transport_link_t transport_link,
				    uint8_t link_id,
				    struct sockaddr_storage *address, struct sockaddr_storage *dst_address)
{
	int listen_sock;
	int savederrno = EINVAL;
	struct epoll_event ev;
	int err;
	tcp_link_info_t *info;
	tcp_handle_info_t *handle_info;

	info = (tcp_link_info_t *)transport_link;
	handle_info = info->transport;

	listen_sock = socket(address->ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (listen_sock < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to create listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_configure_tcp_socket(knet_h, listen_sock, address, "listener") < 0) {
		/* Error already reported */
		goto exit_error;
	}

	if (bind(listen_sock, (struct sockaddr *)address, sizeof(struct sockaddr_storage)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to bind listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (listen(listen_sock, 5) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to listen on listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = listen_sock;
	if (epoll_ctl(handle_info->listen_epollfd, EPOLL_CTL_ADD, listen_sock, &ev)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TCP_LINK_T, "Unable to add listener to epoll pool: %s",
			strerror(savederrno));
		goto exit_error;
	}
	info->listen_sock = listen_sock;
	log_debug(knet_h, KNET_SUB_TCP_LINK_T, "Listening on fd %d for %s", listen_sock, _transport_print_ip(address));
	return 0;

exit_error:
	errno = savederrno;
	return err;
}


static int tcp_link_allocate(knet_handle_t knet_h, knet_transport_t transport,
			      struct knet_link *link,
			      knet_transport_link_t *transport_link,
			      uint8_t link_id,
			      struct sockaddr_storage *address, struct sockaddr_storage *dst_address,
			      int *send_sock)
{
	int savederrno = EINVAL;
	int err;
	int i;
	tcp_link_info_t *info;
	tcp_handle_info_t *handle_info;

	info = malloc(sizeof(tcp_link_info_t));
	if (!info) {
		return -1;
	}
	info->knet_handle = knet_h;
	memcpy(&info->dst_address, dst_address, sizeof(struct sockaddr_storage));
	handle_info = transport;
	info->link = link;
	info->on_epoll = 0;
	info->sendrecv_sock = -1;
	for (i=0; i< MAX_ACCEPTED_SOCKS; i++) {
		info->accepted_socks[i] = -1;
	}

	info->sendrecv_sock = _create_connect_socket(knet_h, handle_info, info, 1);
	if (info->sendrecv_sock == -1) {
		free(info);
		err = -1;
		goto exit_error;
	}

	info->transport = transport;
	qb_list_add(&info->list, &handle_info->links_list);

	*transport_link = (knet_transport_link_t *)info;
	*send_sock = info->sendrecv_sock;
	return 0;

exit_error:
	errno = savederrno;
	return err;
}

static int tcp_link_free(knet_transport_link_t transport)
{
	tcp_link_info_t *info = (tcp_link_info_t *)transport;
	int i;

	close(info->sendrecv_sock);
	close(info->listen_sock);
	for (i=0; i< MAX_ACCEPTED_SOCKS; i++) {
		if (info->accepted_socks[i] > -1) {
			close(info->accepted_socks[i]);
		}
	}

	qb_list_del(&info->list);

	/* Remove from epoll */
	free(transport);
	return 0;
}

static int tcp_link_get_mtu_overhead(knet_transport_t transport)
{
	return KNET_PMTUD_TCP_OVERHEAD;
}

static knet_transport_ops_t tcp_transport_ops = {

	.handle_allocate = tcp_handle_allocate,
	.handle_free = tcp_handle_free,
	.handle_fd_eof = tcp_handle_fd_eof,

	.link_allocate = tcp_link_allocate,
	.link_listener_start = tcp_link_listener_start,
	.link_free = tcp_link_free,
	.link_get_mtu_overhead = tcp_link_get_mtu_overhead,
	.transport_name = "TCP",
};


knet_transport_ops_t *get_tcp_transport()
{
	return &tcp_transport_ops;
}
