/*
 * Copyright (C) 2016-2021 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <assert.h>

#include "compat.h"
#include "host.h"
#include "links.h"
#include "links_acl.h"
#include "links_acl_ip.h"
#include "logging.h"
#include "netutils.h"
#include "common.h"
#include "transport_common.h"
#include "transports.h"
#include "threads_common.h"

#ifdef HAVE_NETINET_SCTP_H
#include <netinet/sctp.h>
#include "transport_sctp.h"

typedef struct sctp_handle_info {
	struct qb_list_head listen_links_list;
	struct qb_list_head connect_links_list;
	int connect_epollfd;
	int connectsockfd[2];
	int listen_epollfd;
	int listensockfd[2];
	pthread_t connect_thread;
	pthread_t listen_thread;
	socklen_t event_subscribe_kernel_size;
	char *event_subscribe_buffer;
} sctp_handle_info_t;

/*
 * use by fd_tracker data type
 */
#define SCTP_NO_LINK_INFO       0
#define SCTP_LISTENER_LINK_INFO 1
#define SCTP_ACCEPTED_LINK_INFO 2
#define SCTP_CONNECT_LINK_INFO  3

/*
 * this value is per listener
 */
#define MAX_ACCEPTED_SOCKS 256

typedef struct sctp_listen_link_info {
	struct qb_list_head list;
	int listen_sock;
	int accepted_socks[MAX_ACCEPTED_SOCKS];
	struct sockaddr_storage src_address;
	int on_listener_epoll;
	int on_rx_epoll;
	int sock_shutdown;
} sctp_listen_link_info_t;

typedef struct sctp_accepted_link_info {
	char mread_buf[KNET_DATABUFSIZE];
	ssize_t mread_len;
	sctp_listen_link_info_t *link_info;
} sctp_accepted_link_info_t ;

typedef struct sctp_connect_link_info {
	struct qb_list_head list;
	sctp_listen_link_info_t *listener;
	struct knet_link *link;
	struct sockaddr_storage dst_address;
	int connect_sock;
	int on_rx_epoll;
	int close_sock;
	int sock_shutdown;
} sctp_connect_link_info_t;

/*
 * socket handling functions
 *
 * those functions do NOT perform locking. locking
 * should be handled in the right context from callers
 */

/*
 * sockets are removed from rx_epoll from callers
 * see also error handling functions
 */
static int _close_connect_socket(knet_handle_t knet_h, struct knet_link *kn_link)
{
	int err = 0, savederrno = 0;
	struct epoll_event ev;
	sctp_connect_link_info_t *info = kn_link->transport_link;

	if (info->connect_sock != -1) {
		if (info->on_rx_epoll) {
			memset(&ev, 0, sizeof(struct epoll_event));
			ev.events = EPOLLIN;
			ev.data.fd = info->connect_sock;
			if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, info->connect_sock, &ev)) {
				savederrno = errno;
				err = -1;
				log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to remove connected socket from epoll pool: %s",
				strerror(savederrno));
				goto exit_error;
			}
			info->on_rx_epoll = 0;
		}

		if (_set_fd_tracker(knet_h, info->connect_sock, KNET_MAX_TRANSPORTS, SCTP_NO_LINK_INFO, 0, NULL) < 0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to set fd tracker: %s",
				strerror(savederrno));
		} else {
			close(info->connect_sock);
			info->connect_sock = -1;
		}
	}

exit_error:
	errno = savederrno;
	return err;
}

static int _enable_sctp_notifications(knet_handle_t knet_h, int sock, const char *type)
{
	int err = 0, savederrno = 0;
	sctp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];

	if (setsockopt(sock, IPPROTO_SCTP, SCTP_EVENTS,
		       handle_info->event_subscribe_buffer,
		       handle_info->event_subscribe_kernel_size) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to enable %s events: %s",
			type, strerror(savederrno));
	}

	errno = savederrno;
	return err;
}

static int _configure_sctp_socket(knet_handle_t knet_h, int sock, struct sockaddr_storage *address, uint64_t flags, const char *type)
{
	int err = 0, savederrno = 0;
	int value;
	int level;

#ifdef SOL_SCTP
	level = SOL_SCTP;
#else
	level = IPPROTO_SCTP;
#endif

	if (_configure_transport_socket(knet_h, sock, address, flags, type) < 0) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

	value = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set reuseaddr on socket %d: %s",
			sock, strerror(savederrno));
		goto exit_error;
	}

	value = 1;
	if (setsockopt(sock, level, SCTP_NODELAY, &value, sizeof(value)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set sctp nodelay: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_enable_sctp_notifications(knet_h, sock, type) < 0) {
		savederrno = errno;
		err = -1;
	}

exit_error:
	errno = savederrno;
	return err;
}

static int _reconnect_socket(knet_handle_t knet_h, struct knet_link *kn_link)
{
	int err = 0, savederrno = 0;
	sctp_connect_link_info_t *info = kn_link->transport_link;

	if (connect(info->connect_sock, (struct sockaddr *)&kn_link->dst_addr, sockaddr_len(&kn_link->dst_addr)) < 0) {
		savederrno = errno;
		log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "SCTP socket %d received error: %s", info->connect_sock, strerror(savederrno));
		if ((savederrno != EALREADY) && (savederrno != EINPROGRESS) && (savederrno != EISCONN)) {
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to connect SCTP socket %d: %s",
				info->connect_sock, strerror(savederrno));
		}
	}

	errno = savederrno;
	return err;
}

static int _create_connect_socket(knet_handle_t knet_h, struct knet_link *kn_link)
{
	int err = 0, savederrno = 0;
	struct epoll_event ev;
	sctp_connect_link_info_t *info = kn_link->transport_link;
	int connect_sock;
	struct sockaddr_storage connect_addr;

	connect_sock = socket(kn_link->dst_addr.ss_family, SOCK_STREAM, IPPROTO_SCTP);
	if (connect_sock < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to create send/recv socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_configure_sctp_socket(knet_h, connect_sock, &kn_link->dst_addr, kn_link->flags, "SCTP connect") < 0) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

	memset(&connect_addr, 0, sizeof(struct sockaddr_storage));
	if (knet_strtoaddr(kn_link->status.src_ipaddr, "0", &connect_addr, sockaddr_len(&connect_addr)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to resolve connecting socket: %s",
			strerror(savederrno));
		goto exit_error;

	}

	if (bind(connect_sock, (struct sockaddr *)&connect_addr, sockaddr_len(&connect_addr)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to bind connecting socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_set_fd_tracker(knet_h, connect_sock, KNET_TRANSPORT_SCTP, SCTP_CONNECT_LINK_INFO, sockaddr_len(&kn_link->src_addr), info) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to set fd tracker: %s",
			strerror(savederrno));
		goto exit_error;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = connect_sock;
	if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_ADD, connect_sock, &ev)) {
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to add connected socket to epoll pool: %s",
			strerror(errno));
	}
	info->on_rx_epoll = 1;

	info->connect_sock = connect_sock;
	info->close_sock = 0;
	kn_link->outsock = info->connect_sock;

	if (_reconnect_socket(knet_h, kn_link) < 0) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

exit_error:
	if (err) {
		if (connect_sock >= 0) {
			close(connect_sock);
		}
	}
	errno = savederrno;
	return err;
}

static void _lock_sleep_relock(knet_handle_t knet_h)
{
	int i = 0;

	/* Don't hold onto the lock while sleeping */
	pthread_rwlock_unlock(&knet_h->global_rwlock);

	while (i < 5) {
		usleep(KNET_THREADS_TIMERES / 16);
		if (!pthread_rwlock_rdlock(&knet_h->global_rwlock)) {
			/*
			 * lock acquired, we can go out
			 */
			return;
		} else {
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to get read lock!");
			i++;
		}
	}
	/*
	 * time to crash! if we cannot re-acquire the lock
	 * there is no easy way out of this one
	 */
	assert(0);
}

int sctp_transport_tx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno)
{
	sctp_connect_link_info_t *connect_info = knet_h->knet_transport_fd_tracker[sockfd].data;
	sctp_accepted_link_info_t *accepted_info = knet_h->knet_transport_fd_tracker[sockfd].data;
	sctp_listen_link_info_t *listen_info;

	if (recv_err < 0) {
		switch (knet_h->knet_transport_fd_tracker[sockfd].data_type) {
			case SCTP_CONNECT_LINK_INFO:
				if (connect_info->link->transport_connected == 0) {
					return -1;
				}
				break;
			case SCTP_ACCEPTED_LINK_INFO:
				listen_info = accepted_info->link_info;
				if (listen_info->listen_sock != sockfd) {
					if (listen_info->on_rx_epoll == 0) {
						return -1;
					}
				}
				break;
		}
		if (recv_errno == EAGAIN) {
#ifdef DEBUG
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Sock: %d is overloaded. Slowing TX down", sockfd);
#endif
			_lock_sleep_relock(knet_h);
			return 1;
		}
		return -1;
	}
	return 0;
}

/*
 * socket error management functions
 *
 * both called with global read lock.
 *
 * NOTE: we need to remove the fd from the epoll as soon as possible
 *       even before we notify the respective thread to take care of it
 *       because scheduling can make it so that this thread will overload
 *       and the threads supposed to take care of the error will never
 *       be able to take action.
 *       we CANNOT handle FDs here directly (close/reconnect/etc) due
 *       to locking context. We need to delegate that to their respective
 *       management threads within the global write lock.
 *
 * this function is called from:
 * - RX thread with recv_err <= 0 directly on recvmmsg error
 * - transport_rx_is_data when msg_len == 0 (recv_err = 1)
 * - transport_rx_is_data on notification (recv_err = 2)
 *
 * basically this small abuse of recv_err is to detect notifications
 * generated by sockets created by listen().
 */
int sctp_transport_rx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno)
{
	struct epoll_event ev;
	sctp_accepted_link_info_t *accepted_info = knet_h->knet_transport_fd_tracker[sockfd].data;
	sctp_listen_link_info_t *listen_info;
	sctp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];

	switch (knet_h->knet_transport_fd_tracker[sockfd].data_type) {
		case SCTP_CONNECT_LINK_INFO:
			/*
			 * all connect link have notifications enabled
			 * and we accept only data from notification and
			 * generic recvmmsg errors.
			 *
			 * Errors generated by msg_len 0 can be ignored because
			 * they follow a notification (double notification)
			 */
			if (recv_err != 1) {
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Notifying connect thread that sockfd %d received an error", sockfd);
				if (sendto(handle_info->connectsockfd[1], &sockfd, sizeof(int), MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0) != sizeof(int)) {
					log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to notify connect thread: %s", strerror(errno));
				}
			}
			break;
		case SCTP_ACCEPTED_LINK_INFO:
			listen_info = accepted_info->link_info;
			if (listen_info->listen_sock != sockfd) {
				if (recv_err != 1) {
					if (listen_info->on_rx_epoll) {
						memset(&ev, 0, sizeof(struct epoll_event));
						ev.events = EPOLLIN;
						ev.data.fd = sockfd;
						if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, sockfd, &ev)) {
							log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to remove EOFed socket from epoll pool: %s",
							strerror(errno));
							return -1;
						}
						listen_info->on_rx_epoll = 0;
					}
					log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Notifying listen thread that sockfd %d received an error", sockfd);
					if (sendto(handle_info->listensockfd[1], &sockfd, sizeof(int), MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0) != sizeof(int)) {
						log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to notify listen thread: %s", strerror(errno));
					}
				}
			} else {
				/*
				 * this means the listen() socket has generated
				 * a notification. now what? :-)
				 */
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Received stray notification for listen() socket %d", sockfd);
			}
			break;
		default:
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Received unknown notification? %d", sockfd);
			break;
	}
	/*
	 * Under RX pressure we need to give time to IPC to pick up the message
	 */

	_lock_sleep_relock(knet_h);
	return 0;
}

/*
 * NOTE: sctp_transport_rx_is_data is called with global rdlock
 *       delegate any FD error management to sctp_transport_rx_sock_error
 *       and keep this code to parsing incoming data only
 */
int sctp_transport_rx_is_data(knet_handle_t knet_h, int sockfd, struct knet_mmsghdr *msg)
{
	size_t i;
	struct iovec *iov = msg->msg_hdr.msg_iov;
	size_t iovlen = msg->msg_hdr.msg_iovlen;
	struct sctp_assoc_change *sac;
	union sctp_notification  *snp;
	sctp_accepted_link_info_t *listen_info = knet_h->knet_transport_fd_tracker[sockfd].data;
	sctp_connect_link_info_t *connect_info = knet_h->knet_transport_fd_tracker[sockfd].data;

	if (!(msg->msg_hdr.msg_flags & MSG_NOTIFICATION)) {
		if (msg->msg_len == 0) {
			/*
			 * NOTE: with event notification enabled, we receive error twice:
			 *       1) from the event notification
			 *       2) followed by a 0 byte msg_len
			 *
			 * the event handler should take care to avoid #2 by stopping
			 * the rx thread from processing more packets than necessary.
			 */
			if (knet_h->knet_transport_fd_tracker[sockfd].data_type == SCTP_CONNECT_LINK_INFO) {
				if (connect_info->sock_shutdown) {
					return KNET_TRANSPORT_RX_OOB_DATA_CONTINUE;
				}
			} else {
				if (listen_info->link_info->sock_shutdown) {
					return KNET_TRANSPORT_RX_OOB_DATA_CONTINUE;
				}
			}
			/*
			 * this is pretty much dead code and we should never hit it.
			 * keep it for safety and avoid the rx thread to process
			 * bad info / data.
			 */
			return KNET_TRANSPORT_RX_NOT_DATA_STOP;
		}
		/*
		 * missing MSG_EOR has to be treated as a short read
		 * from the socket and we need to fill in the mread buf
		 * while we wait for MSG_EOR
		 */
		if (!(msg->msg_hdr.msg_flags & MSG_EOR)) {
			/*
			 * copy the incoming data into mread_buf + mread_len (incremental)
			 * and increase mread_len
			 */
			memmove(listen_info->mread_buf + listen_info->mread_len, iov->iov_base, msg->msg_len);
			listen_info->mread_len = listen_info->mread_len + msg->msg_len;
			return KNET_TRANSPORT_RX_NOT_DATA_CONTINUE;
		}
		/*
		 * got EOR.
		 * if mread_len is > 0 we are completing a packet from short reads
		 * complete reassembling the packet in mread_buf, copy it back in the iov
		 * and set the iov/msg len numbers (size) correctly
		 */
		if (listen_info->mread_len) {
			/*
			 * add last fragment to mread_buf
			 */
			memmove(listen_info->mread_buf + listen_info->mread_len, iov->iov_base, msg->msg_len);
			listen_info->mread_len = listen_info->mread_len + msg->msg_len;
			/*
			 * move all back into the iovec
			 */
			memmove(iov->iov_base, listen_info->mread_buf, listen_info->mread_len);
			msg->msg_len = listen_info->mread_len;
			listen_info->mread_len = 0;
		}
		return KNET_TRANSPORT_RX_IS_DATA;
	}

	if (!(msg->msg_hdr.msg_flags & MSG_EOR)) {
		return KNET_TRANSPORT_RX_NOT_DATA_STOP;
	}

	for (i = 0; i < iovlen; i++) {
		snp = iov[i].iov_base;

		switch (snp->sn_header.sn_type) {
			case SCTP_ASSOC_CHANGE:
				sac = &snp->sn_assoc_change;
				switch (sac->sac_state) {
					case SCTP_COMM_LOST:
						log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp assoc change socket %d: comm_lost", sockfd);
						if (knet_h->knet_transport_fd_tracker[sockfd].data_type == SCTP_CONNECT_LINK_INFO) {
							connect_info->close_sock = 1;
							connect_info->link->transport_connected = 0;
						}
						sctp_transport_rx_sock_error(knet_h, sockfd, 2, 0);
						return KNET_TRANSPORT_RX_OOB_DATA_STOP;
						break;
					case SCTP_COMM_UP:
						log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp assoc change socket %d: comm_up", sockfd);
						if (knet_h->knet_transport_fd_tracker[sockfd].data_type == SCTP_CONNECT_LINK_INFO) {
							connect_info->link->transport_connected = 1;
						}
						break;
					case SCTP_RESTART:
						log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp assoc change socket %d: restart", sockfd);
						break;
					case SCTP_SHUTDOWN_COMP:
						log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp assoc change socket %d: shutdown comp", sockfd);
						if (knet_h->knet_transport_fd_tracker[sockfd].data_type == SCTP_CONNECT_LINK_INFO) {
							connect_info->close_sock = 1;
						}
						sctp_transport_rx_sock_error(knet_h, sockfd, 2, 0);
						return KNET_TRANSPORT_RX_OOB_DATA_STOP;
						break;
					case SCTP_CANT_STR_ASSOC:
						log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp assoc change socket %d: cant str assoc", sockfd);
						sctp_transport_rx_sock_error(knet_h, sockfd, 2, 0);
						break;
					default:
						log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp assoc change socket %d: unknown %d", sockfd, sac->sac_state);
						break;
				}
				break;
			case SCTP_SHUTDOWN_EVENT:
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp shutdown event socket %d", sockfd);
				if (knet_h->knet_transport_fd_tracker[sockfd].data_type == SCTP_CONNECT_LINK_INFO) {
					connect_info->link->transport_connected = 0;
					connect_info->sock_shutdown = 1;
				} else {
					listen_info->link_info->sock_shutdown = 1;
				}
				break;
			case SCTP_SEND_FAILED:
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp send failed socket: %d", sockfd);
				break;
			case SCTP_PEER_ADDR_CHANGE:
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp peer addr change socket %d", sockfd);
				break;
			case SCTP_REMOTE_ERROR:
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp remote error socket %d", sockfd);
				break;
			default:
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] unknown sctp event socket: %d type: %hu", sockfd, snp->sn_header.sn_type);
				break;
		}
	}
	return KNET_TRANSPORT_RX_OOB_DATA_CONTINUE;
}

int sctp_transport_link_is_down(knet_handle_t knet_h, struct knet_link *kn_link)
{
	sctp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];
	sctp_connect_link_info_t *info = kn_link->transport_link;

	kn_link->transport_connected = 0;
	info->close_sock = 1;

	log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Notifying connect thread that sockfd %d received a link down event", info->connect_sock);
	if (sendto(handle_info->connectsockfd[1], &info->connect_sock, sizeof(int), MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0) != sizeof(int)) {
		log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to notify connect thread: %s", strerror(errno));
	}

	return 0;
}

/*
 * connect / outgoing socket management thread
 */

/*
 * _handle_connected_sctp* are called with a global write lock
 * from the connect_thread
 */
static void _handle_connected_sctp_socket(knet_handle_t knet_h, int connect_sock)
{
	int err;
	unsigned int status, len = sizeof(status);
	sctp_connect_link_info_t *info = knet_h->knet_transport_fd_tracker[connect_sock].data;
	struct knet_link *kn_link = info->link;

	if (info->close_sock) {
		if (_close_connect_socket(knet_h, kn_link) < 0) {
			log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to close sock %d from _handle_connected_sctp_socket: %s", connect_sock, strerror(errno));
			return;
		}
		info->close_sock = 0;
		if (_create_connect_socket(knet_h, kn_link) < 0) {
			log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to recreate connecting sock! %s", strerror(errno));
			return;
		}
	}

	_reconnect_socket(knet_h, info->link);

	err = getsockopt(connect_sock, SOL_SOCKET, SO_ERROR, &status, &len);
	if (err) {
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "SCTP getsockopt() on connecting socket %d failed: %s",
			connect_sock, strerror(errno));
		return;
	}

	if (status) {
		log_info(knet_h, KNET_SUB_TRANSP_SCTP, "SCTP connect on %d to %s port %s failed: %s",
			 connect_sock, kn_link->status.dst_ipaddr, kn_link->status.dst_port,
			 strerror(status));

		/*
		 * No need to create a new socket if connect failed,
		 * just retry connect
		 */
		return;
	}

	log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "SCTP handler fd %d now connected to %s port %s",
		  connect_sock,
		  kn_link->status.dst_ipaddr, kn_link->status.dst_port);
}

static void _handle_connected_sctp_notifications(knet_handle_t knet_h)
{
	int sockfd = -1;
	sctp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];

	if (recv(handle_info->connectsockfd[0], &sockfd, sizeof(int), MSG_DONTWAIT | MSG_NOSIGNAL) != sizeof(int)) {
		log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Short read on connectsockfd");
		return;
	}

	if (_is_valid_fd(knet_h, sockfd) < 1) {
		log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Received stray notification for connected socket fd error");
		return;
	}

	/*
	 * revalidate sockfd
	 */
	if ((sockfd < 0) || (sockfd >= KNET_MAX_FDS)) {
		return;
	}

	log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Processing connected error on socket: %d", sockfd);

	_handle_connected_sctp_socket(knet_h, sockfd);
}

static void *_sctp_connect_thread(void *data)
{
	int savederrno;
	int i, nev;
	knet_handle_t knet_h = (knet_handle_t) data;
	sctp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];

	set_thread_status(knet_h, KNET_THREAD_SCTP_CONN, KNET_THREAD_STARTED);

	memset(&events, 0, sizeof(events));

	while (!shutdown_in_progress(knet_h)) {
		nev = epoll_wait(handle_info->connect_epollfd, events, KNET_EPOLL_MAX_EVENTS, KNET_THREADS_TIMERES / 1000);

		/*
		 * we use timeout to detect if thread is shutting down
		 */
		if (nev == 0) {
			continue;
		}

		if (nev < 0) {
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "SCTP connect handler EPOLL ERROR: %s",
				  strerror(errno));
			continue;
		}

		/*
		 * Sort out which FD has a connection
		 */
		savederrno = get_global_wrlock(knet_h);
		if (savederrno) {
			log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to get write lock: %s",
				strerror(savederrno));
			continue;
		}

		/*
		 * minor optimization: deduplicate events
		 *
		 * in some cases we can receive multiple notifcations
		 * of the same FD having issues or need handling.
		 * It's enough to process it once even tho it's safe
		 * to handle them multiple times.
		 */
		for (i = 0; i < nev; i++) {
			if (events[i].data.fd == handle_info->connectsockfd[0]) {
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Received notification from rx_error for connected socket");
				_handle_connected_sctp_notifications(knet_h);
			} else {
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Received stray notification on connected sockfd %d\n", events[i].data.fd);
			}
		}
		pthread_rwlock_unlock(&knet_h->global_rwlock);
		/*
		 * this thread can generate events for itself.
		 * we need to sleep in between loops to allow other threads
		 * to be scheduled
		 */
		usleep(knet_h->reconnect_int * 1000);
	}

	set_thread_status(knet_h, KNET_THREAD_SCTP_CONN, KNET_THREAD_STOPPED);

	return NULL;
}

/*
 * listen/incoming connections management thread
 */

/*
 * Listener received a new connection
 * called with a write lock from main thread
 */
static void _handle_incoming_sctp(knet_handle_t knet_h, int listen_sock)
{
	int err = 0, savederrno = 0;
	int new_fd;
	int i = -1;
	sctp_listen_link_info_t *info = knet_h->knet_transport_fd_tracker[listen_sock].data;
	struct epoll_event ev;
	struct sockaddr_storage ss;
	socklen_t sock_len = sizeof(ss);
	char addr_str[KNET_MAX_HOST_LEN];
	char port_str[KNET_MAX_PORT_LEN];
	sctp_accepted_link_info_t *accept_info = NULL;
	struct knet_host *host;
	struct knet_link *kn_link;
	int link_idx;
	sctp_connect_link_info_t *this_link_connect_info;
	sctp_listen_link_info_t *this_link_listen_info;
	int pass_acl = 0;

	memset(&ss, 0, sizeof(ss));

	new_fd = accept(listen_sock, (struct sockaddr *)&ss, &sock_len);
	if (new_fd < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Incoming: accept error: %s", strerror(errno));
		goto exit_error;
	}

	if (knet_addrtostr(&ss, sizeof(ss),
			   addr_str, KNET_MAX_HOST_LEN,
			   port_str, KNET_MAX_PORT_LEN) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Incoming: unable to gather socket info");
		goto exit_error;
	}

	log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Incoming: received connection from: %s port: %s",
						addr_str, port_str);

	if (knet_h->use_access_lists) {
		for (host = knet_h->host_head; host != NULL; host = host->next) {
			for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
				kn_link = &host->link[link_idx];

				if ((kn_link->configured) && (kn_link->transport == KNET_TRANSPORT_SCTP)) {
					this_link_connect_info = kn_link->transport_link;
					this_link_listen_info = this_link_connect_info->listener;
					if ((this_link_listen_info->listen_sock == listen_sock) &&
					    (check_validate(knet_h, kn_link, &ss))) {
						pass_acl = 1;
						break;
					}
				}
			}
			if (pass_acl) {
				break;
			}
		}
		if (!pass_acl) {
			savederrno = EINVAL;
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Connection rejected from %s/%s", addr_str, port_str);
			close(new_fd);
			errno = savederrno;
			return;
		}
	}

	/*
	 * Keep a track of all accepted FDs
	 */
	for (i=0; i<MAX_ACCEPTED_SOCKS; i++) {
		if (info->accepted_socks[i] == -1) {
			info->accepted_socks[i] = new_fd;
			break;
		}
	}

	if (i == MAX_ACCEPTED_SOCKS) {
		errno = EBUSY;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Incoming: too many connections!");
		goto exit_error;
	}

	if (_configure_common_socket(knet_h, new_fd, 0, "SCTP incoming") < 0) { /* Inherit flags from listener? */
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

	if (_enable_sctp_notifications(knet_h, new_fd, "Incoming connection") < 0) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

	accept_info = malloc(sizeof(sctp_accepted_link_info_t));
	if (!accept_info) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}
	memset(accept_info, 0, sizeof(sctp_accepted_link_info_t));

	accept_info->link_info = info;

	if (_set_fd_tracker(knet_h, new_fd, KNET_TRANSPORT_SCTP, SCTP_ACCEPTED_LINK_INFO,
			    knet_h->knet_transport_fd_tracker[listen_sock].sockaddr_len,
			    accept_info) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to set fd tracker: %s",
			strerror(errno));
		goto exit_error;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = new_fd;
	if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_ADD, new_fd, &ev)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Incoming: unable to add accepted socket %d to epoll pool: %s",
			new_fd, strerror(errno));
		goto exit_error;
	}
	info->on_rx_epoll = 1;

	log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Incoming: accepted new fd %d for %s/%s (listen fd: %d). index: %d",
		  new_fd, addr_str, port_str, info->listen_sock, i);

exit_error:
	if (err) {
		if ((i >= 0) && (i < MAX_ACCEPTED_SOCKS)) {
			info->accepted_socks[i] = -1;
		}
		/*
		 * check the error to make coverity scan happy.
		 * _set_fd_tracker cannot fail at this stage
		 */
		if (_set_fd_tracker(knet_h, new_fd, KNET_MAX_TRANSPORTS, SCTP_NO_LINK_INFO, 0, NULL) < 0){
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to update fdtracker for socket %d", new_fd);
		}
		free(accept_info);
		if (new_fd >= 0) {
			close(new_fd);
		}
	}
	errno = savederrno;
	return;
}

/*
 * Listen thread received a notification of a bad socket that needs closing
 * called with a write lock from main thread
 */
static void _handle_listen_sctp_errors(knet_handle_t knet_h)
{
	int sockfd = -1;
	sctp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];
	sctp_accepted_link_info_t *accept_info;
	sctp_listen_link_info_t *info;
	struct knet_host *host;
	int link_idx;
	int i;

	if (recv(handle_info->listensockfd[0], &sockfd, sizeof(int), MSG_DONTWAIT | MSG_NOSIGNAL) != sizeof(int)) {
		log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Short read on listensockfd");
		return;
	}

	if (_is_valid_fd(knet_h, sockfd) < 1) {
		log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Received stray notification for listen socket fd error");
		return;
	}

	/*
	 * revalidate sockfd
	 */
	if ((sockfd < 0) || (sockfd >= KNET_MAX_FDS)) {
		return;
	}

	log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Processing listen error on socket: %d", sockfd);

	accept_info = knet_h->knet_transport_fd_tracker[sockfd].data;
	info = accept_info->link_info;

	/*
	 * clear all links using this accepted socket as
	 * outbound dynamically connected socket
	 */

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
			if ((host->link[link_idx].dynamic == KNET_LINK_DYNIP) &&
			    (host->link[link_idx].outsock == sockfd)) {
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Found dynamic connection on host %d link %d (%d)",
					  host->host_id, link_idx, sockfd);
				host->link[link_idx].status.dynconnected = 0;
				host->link[link_idx].transport_connected = 0;
				host->link[link_idx].outsock = 0;
				memset(&host->link[link_idx].dst_addr, 0, sizeof(struct sockaddr_storage));
			}
		}
	}

	for (i=0; i<MAX_ACCEPTED_SOCKS; i++) {
		if (sockfd == info->accepted_socks[i]) {
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Closing accepted socket %d", sockfd);
			/*
			 * check the error to make coverity scan happy.
			 * _set_fd_tracker cannot fail at this stage
			 */
			if (_set_fd_tracker(knet_h, sockfd, KNET_MAX_TRANSPORTS, SCTP_NO_LINK_INFO, 0, NULL) < 0) {
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to update fdtracker for socket %d", sockfd);
			}
			info->accepted_socks[i] = -1;
			free(accept_info);
			close(sockfd);
			break; /* Keeps covscan happy */
		}
	}
}

static void *_sctp_listen_thread(void *data)
{
	int savederrno;
	int i, nev;
	knet_handle_t knet_h = (knet_handle_t) data;
	sctp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];

	set_thread_status(knet_h, KNET_THREAD_SCTP_LISTEN, KNET_THREAD_STARTED);

	memset(&events, 0, sizeof(events));

	while (!shutdown_in_progress(knet_h)) {
		nev = epoll_wait(handle_info->listen_epollfd, events, KNET_EPOLL_MAX_EVENTS, KNET_THREADS_TIMERES / 1000);

		/*
		 * we use timeout to detect if thread is shutting down
		 */
		if (nev == 0) {
			continue;
		}

		if (nev < 0) {
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "SCTP listen handler EPOLL ERROR: %s",
				  strerror(errno));
			continue;
		}

		savederrno = get_global_wrlock(knet_h);
		if (savederrno) {
			log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to get write lock: %s",
				strerror(savederrno));
			continue;
		}
		/*
		 * Sort out which FD has an incoming connection
		 */
		for (i = 0; i < nev; i++) {
			if (events[i].data.fd == handle_info->listensockfd[0]) {
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Received notification from rx_error for listener/accepted socket");
				_handle_listen_sctp_errors(knet_h);
			} else {
				if (_is_valid_fd(knet_h, events[i].data.fd) == 1) {
					_handle_incoming_sctp(knet_h, events[i].data.fd);
				} else {
					log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Received listen notification from invalid socket");
				}
			}

		}
		pthread_rwlock_unlock(&knet_h->global_rwlock);
	}

	set_thread_status(knet_h, KNET_THREAD_SCTP_LISTEN, KNET_THREAD_STOPPED);

	return NULL;
}

/*
 * sctp_link_listener_start/stop are called in global write lock
 * context from set_config and clear_config.
 */
static sctp_listen_link_info_t *sctp_link_listener_start(knet_handle_t knet_h, struct knet_link *kn_link)
{
	int err = 0, savederrno = 0;
	int listen_sock = -1;
	struct epoll_event ev;
	sctp_listen_link_info_t *info = NULL;
	sctp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];

	/*
	 * Only allocate a new listener if src address is different
	 */
	qb_list_for_each_entry(info, &handle_info->listen_links_list, list) {
		if (memcmp(&info->src_address, &kn_link->src_addr, sizeof(struct sockaddr_storage)) == 0) {
			if ((check_add(knet_h, kn_link, -1,
				       &kn_link->dst_addr, &kn_link->dst_addr, CHECK_TYPE_ADDRESS, CHECK_ACCEPT) < 0) && (errno != EEXIST)) {
				return NULL;
			}
			return info;
		}
	}

	info = malloc(sizeof(sctp_listen_link_info_t));
	if (!info) {
		err = -1;
		goto exit_error;
	}

	memset(info, 0, sizeof(sctp_listen_link_info_t));

	memset(info->accepted_socks, -1, sizeof(info->accepted_socks));
	memmove(&info->src_address, &kn_link->src_addr, sizeof(struct sockaddr_storage));

	listen_sock = socket(kn_link->src_addr.ss_family, SOCK_STREAM, IPPROTO_SCTP);
	if (listen_sock < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to create listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_configure_sctp_socket(knet_h, listen_sock, &kn_link->src_addr, kn_link->flags, "SCTP listener") < 0) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

	if (bind(listen_sock, (struct sockaddr *)&kn_link->src_addr, sockaddr_len(&kn_link->src_addr)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to bind listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (listen(listen_sock, 5) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to listen on listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_set_fd_tracker(knet_h, listen_sock, KNET_TRANSPORT_SCTP, SCTP_LISTENER_LINK_INFO, sockaddr_len(&kn_link->src_addr), info) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to set fd tracker: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if ((check_add(knet_h, kn_link, -1,
		       &kn_link->dst_addr, &kn_link->dst_addr, CHECK_TYPE_ADDRESS, CHECK_ACCEPT) < 0) && (errno != EEXIST)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to configure default access lists: %s",
			strerror(savederrno));
		goto exit_error;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = listen_sock;
	if (epoll_ctl(handle_info->listen_epollfd, EPOLL_CTL_ADD, listen_sock, &ev)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to add listener to epoll pool: %s",
			strerror(savederrno));
		goto exit_error;
	}
	info->on_listener_epoll = 1;

	info->listen_sock = listen_sock;
	qb_list_add(&info->list, &handle_info->listen_links_list);

	log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Listening on fd %d for %s:%s", listen_sock, kn_link->status.src_ipaddr, kn_link->status.src_port);

exit_error:
	if (err) {
		if ((info) && (info->on_listener_epoll)) {
			epoll_ctl(handle_info->listen_epollfd, EPOLL_CTL_DEL, listen_sock, &ev);
		}
		if (listen_sock >= 0) {
			check_rmall(knet_h, kn_link);
			close(listen_sock);
		}
		if (info) {
			free(info);
			info = NULL;
		}
	}
	errno = savederrno;
	return info;
}

static int sctp_link_listener_stop(knet_handle_t knet_h, struct knet_link *kn_link)
{
	int err = 0, savederrno = 0;
	int found = 0, i;
	struct knet_host *host;
	int link_idx;
	sctp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];
	sctp_connect_link_info_t *this_link_info = kn_link->transport_link;
	sctp_listen_link_info_t *info = this_link_info->listener;
	sctp_connect_link_info_t *link_info;
	struct epoll_event ev;

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
			if (&host->link[link_idx] == kn_link)
				continue;

			link_info = host->link[link_idx].transport_link;
			if ((link_info) &&
			    (link_info->listener == info)) {
				found = 1;
				break;
			}
		}
	}

	if ((check_rm(knet_h, kn_link,
		      &kn_link->dst_addr, &kn_link->dst_addr, CHECK_TYPE_ADDRESS, CHECK_ACCEPT) < 0) && (errno != ENOENT)) {
		log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to remove default access lists for %d", info->listen_sock);
	}

	if (found) {
		this_link_info->listener = NULL;
		log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "SCTP listener socket %d still in use", info->listen_sock);
		savederrno = EBUSY;
		err = -1;
		goto exit_error;
	}

	if (info->on_listener_epoll) {
		memset(&ev, 0, sizeof(struct epoll_event));
		ev.events = EPOLLIN;
		ev.data.fd = info->listen_sock;
		if (epoll_ctl(handle_info->listen_epollfd, EPOLL_CTL_DEL, info->listen_sock, &ev)) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to remove listener to epoll pool: %s",
				strerror(savederrno));
			goto exit_error;
		}
		info->on_listener_epoll = 0;
	}

	if (_set_fd_tracker(knet_h, info->listen_sock, KNET_MAX_TRANSPORTS, SCTP_NO_LINK_INFO, 0, NULL) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to set fd tracker: %s",
			strerror(savederrno));
		goto exit_error;
	}

	check_rmall(knet_h, kn_link);
	close(info->listen_sock);

	for (i=0; i< MAX_ACCEPTED_SOCKS; i++) {
		if (info->accepted_socks[i] > -1) {
			memset(&ev, 0, sizeof(struct epoll_event));
			ev.events = EPOLLIN;
			ev.data.fd = info->accepted_socks[i];
			if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, info->accepted_socks[i], &ev)) {
				log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to remove EOFed socket from epoll pool: %s",
					strerror(errno));
			}
			info->on_rx_epoll = 0;
			free(knet_h->knet_transport_fd_tracker[info->accepted_socks[i]].data);
			close(info->accepted_socks[i]);
			if (_set_fd_tracker(knet_h, info->accepted_socks[i], KNET_MAX_TRANSPORTS, SCTP_NO_LINK_INFO, 0, NULL) < 0) {
				savederrno = errno;
				err = -1;
				log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to set fd tracker: %s",
					strerror(savederrno));
				goto exit_error;
			}
			info->accepted_socks[i] = -1;
		}
	}

	qb_list_del(&info->list);
	free(info);
	this_link_info->listener = NULL;

exit_error:
	errno = savederrno;
	return err;
}

/*
 * Links config/clear. Both called with global wrlock from link_set_config/clear_config
 */
int sctp_transport_link_set_config(knet_handle_t knet_h, struct knet_link *kn_link)
{
	int savederrno = 0, err = 0;
	sctp_connect_link_info_t *info;
	sctp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];

	info = malloc(sizeof(sctp_connect_link_info_t));
	if (!info) {
		goto exit_error;
	}

	memset(info, 0, sizeof(sctp_connect_link_info_t));

	kn_link->transport_link = info;
	info->link = kn_link;

	memmove(&info->dst_address, &kn_link->dst_addr, sizeof(struct sockaddr_storage));
	info->connect_sock = -1;

	info->listener = sctp_link_listener_start(knet_h, kn_link);
	if (!info->listener) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

	if (kn_link->dynamic == KNET_LINK_STATIC) {
		if (_create_connect_socket(knet_h, kn_link) < 0) {
			savederrno = errno;
			err = -1;
			goto exit_error;
		}
		kn_link->outsock = info->connect_sock;
	}

	qb_list_add(&info->list, &handle_info->connect_links_list);

exit_error:
	if (err) {
		if (info) {
			if (info->connect_sock >= 0) {
				close(info->connect_sock);
			}
			if (info->listener) {
				sctp_link_listener_stop(knet_h, kn_link);
			}
			kn_link->transport_link = NULL;
			free(info);
		}
	}
	errno = savederrno;
	return err;
}

/*
 * called with global wrlock
 */
int sctp_transport_link_clear_config(knet_handle_t knet_h, struct knet_link *kn_link)
{
	int err = 0, savederrno = 0;
	sctp_connect_link_info_t *info;

	if (!kn_link) {
		errno = EINVAL;
		return -1;
	}

	info = kn_link->transport_link;

	if (!info) {
		errno = EINVAL;
		return -1;
	}

	if ((sctp_link_listener_stop(knet_h, kn_link) <0) && (errno != EBUSY)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to remove listener transport: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_close_connect_socket(knet_h, kn_link) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to close connected socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	qb_list_del(&info->list);

	free(info);
	kn_link->transport_link = NULL;

exit_error:
	errno = savederrno;
	return err;
}

/*
 * transport_free and transport_init are
 * called only from knet_handle_new and knet_handle_free.
 * all resources (hosts/links) should have been already freed at this point
 * and they are called in a write locked context, hence they
 * don't need their own locking.
 */

int sctp_transport_free(knet_handle_t knet_h)
{
	sctp_handle_info_t *handle_info;
	void *thread_status;
	struct epoll_event ev;

	if (!knet_h->transports[KNET_TRANSPORT_SCTP]) {
		errno = EINVAL;
		return -1;
	}

	handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];

	/*
	 * keep it here while we debug list usage and such
	 */
	if (!qb_list_empty(&handle_info->listen_links_list)) {
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Internal error. listen links list is not empty");
	}
	if (!qb_list_empty(&handle_info->connect_links_list)) {
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Internal error. connect links list is not empty");
	}

	if (handle_info->listen_thread) {
		pthread_cancel(handle_info->listen_thread);
		pthread_join(handle_info->listen_thread, &thread_status);
	}

	if (handle_info->connect_thread) {
		pthread_cancel(handle_info->connect_thread);
		pthread_join(handle_info->connect_thread, &thread_status);
	}

	if (handle_info->listensockfd[0] >= 0) {
		memset(&ev, 0, sizeof(struct epoll_event));
		ev.events = EPOLLIN;
		ev.data.fd = handle_info->listensockfd[0];
		epoll_ctl(handle_info->listen_epollfd, EPOLL_CTL_DEL, handle_info->listensockfd[0], &ev);
	}

	if (handle_info->connectsockfd[0] >= 0) {
		memset(&ev, 0, sizeof(struct epoll_event));
		ev.events = EPOLLIN;
		ev.data.fd = handle_info->connectsockfd[0];
		epoll_ctl(handle_info->connect_epollfd, EPOLL_CTL_DEL, handle_info->connectsockfd[0], &ev);
	}

	_close_socketpair(knet_h, handle_info->connectsockfd);
	_close_socketpair(knet_h, handle_info->listensockfd);

	if (handle_info->listen_epollfd >= 0) {
		close(handle_info->listen_epollfd);
	}

	if (handle_info->connect_epollfd >= 0) {
		close(handle_info->connect_epollfd);
	}

	free(handle_info->event_subscribe_buffer);
	free(handle_info);
	knet_h->transports[KNET_TRANSPORT_SCTP] = NULL;

	return 0;
}

static int _sctp_subscribe_init(knet_handle_t knet_h)
{
	int test_socket, savederrno;
	sctp_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP];
	char dummy_events[100];
	struct sctp_event_subscribe *events;
	/* Below we set the first 6 fields of this expanding struct.
	 * SCTP_EVENTS is deprecated, but SCTP_EVENT is not available
	 * on Linux; on the other hand, FreeBSD and old Linux does not
	 * accept small transfers, so we can't simply use this minimum
	 * everywhere.  Thus we query and store the native size. */
	const unsigned int subscribe_min = 6;

	test_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (test_socket < 0) {
		if (errno == EPROTONOSUPPORT) {
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "SCTP not supported, skipping initialization");
			return 0;
		}
		savederrno = errno;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to create test socket: %s",
			strerror(savederrno));
		return savederrno;
	}
	handle_info->event_subscribe_kernel_size = sizeof dummy_events;
	if (getsockopt(test_socket, IPPROTO_SCTP, SCTP_EVENTS, &dummy_events,
		       &handle_info->event_subscribe_kernel_size)) {
		close(test_socket);
		savederrno = errno;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to query kernel size of struct sctp_event_subscribe: %s",
			strerror(savederrno));
		return savederrno;
	}
	close(test_socket);
	if (handle_info->event_subscribe_kernel_size < subscribe_min) {
		savederrno = ERANGE;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP,
			"No kernel support for the necessary notifications: struct sctp_event_subscribe is %u bytes, %u needed",
			handle_info->event_subscribe_kernel_size, subscribe_min);
		return savederrno;
	}
	events = malloc(handle_info->event_subscribe_kernel_size);
	if (!events) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP,
			"Failed to allocate event subscribe buffer: %s", strerror(savederrno));
		return savederrno;
	}
	memset(events, 0, handle_info->event_subscribe_kernel_size);
	events->sctp_data_io_event = 1;
	events->sctp_association_event = 1;
	events->sctp_address_event = 1;
	events->sctp_send_failure_event = 1;
	events->sctp_peer_error_event = 1;
	events->sctp_shutdown_event = 1;
	handle_info->event_subscribe_buffer = (char *)events;
	log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Size of struct sctp_event_subscribe is %u in kernel, %zu in user space",
		  handle_info->event_subscribe_kernel_size, sizeof(struct sctp_event_subscribe));
	return 0;
}

int sctp_transport_init(knet_handle_t knet_h)
{
	int err = 0, savederrno = 0;
	sctp_handle_info_t *handle_info;
	struct epoll_event ev;

	if (knet_h->transports[KNET_TRANSPORT_SCTP]) {
		errno = EEXIST;
		return -1;
	}

	handle_info = malloc(sizeof(sctp_handle_info_t));
	if (!handle_info) {
		return -1;
	}

	memset(handle_info, 0,sizeof(sctp_handle_info_t));

	knet_h->transports[KNET_TRANSPORT_SCTP] = handle_info;

	savederrno = _sctp_subscribe_init(knet_h);
	if (savederrno) {
		err = -1;
		goto exit_fail;
	}

	qb_list_init(&handle_info->listen_links_list);
	qb_list_init(&handle_info->connect_links_list);

	handle_info->listen_epollfd = epoll_create(KNET_EPOLL_MAX_EVENTS + 1);
	if (handle_info->listen_epollfd < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to create epoll listen fd: %s",
			strerror(savederrno));
		goto exit_fail;
        }

	if (_fdset_cloexec(handle_info->listen_epollfd)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to set CLOEXEC on listen_epollfd: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	handle_info->connect_epollfd = epoll_create(KNET_EPOLL_MAX_EVENTS + 1);
        if (handle_info->connect_epollfd < 0) {
                savederrno = errno;
		err = -1;
                log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to create epoll connect fd: %s",
                        strerror(savederrno));
                goto exit_fail;
        }

	if (_fdset_cloexec(handle_info->connect_epollfd)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to set CLOEXEC on connect_epollfd: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	if (_init_socketpair(knet_h, handle_info->connectsockfd) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to init connect socketpair: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = handle_info->connectsockfd[0];
	if (epoll_ctl(handle_info->connect_epollfd, EPOLL_CTL_ADD, handle_info->connectsockfd[0], &ev)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to add connectsockfd[0] to connect epoll pool: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	if (_init_socketpair(knet_h, handle_info->listensockfd) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to init listen socketpair: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = handle_info->listensockfd[0];
	if (epoll_ctl(handle_info->listen_epollfd, EPOLL_CTL_ADD, handle_info->listensockfd[0], &ev)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to add listensockfd[0] to listen epoll pool: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	/*
	 * Start connect & listener threads
	 */
	set_thread_status(knet_h, KNET_THREAD_SCTP_LISTEN, KNET_THREAD_REGISTERED);
	savederrno = pthread_create(&handle_info->listen_thread, 0, _sctp_listen_thread, (void *) knet_h);
	if (savederrno) {
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to start sctp listen thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	set_thread_status(knet_h, KNET_THREAD_SCTP_CONN, KNET_THREAD_REGISTERED);
	savederrno = pthread_create(&handle_info->connect_thread, 0, _sctp_connect_thread, (void *) knet_h);
	if (savederrno) {
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to start sctp connect thread: %s",
			strerror(savederrno));
		goto exit_fail;
	}

exit_fail:
	if (err < 0) {
		sctp_transport_free(knet_h);
	}
	errno = savederrno;
	return err;
}

int sctp_transport_link_dyn_connect(knet_handle_t knet_h, int sockfd, struct knet_link *kn_link)
{
	kn_link->outsock = sockfd;
	kn_link->status.dynconnected = 1;
	kn_link->transport_connected = 1;
	return 0;
}

int sctp_transport_link_get_acl_fd(knet_handle_t knet_h, struct knet_link *kn_link)
{
	sctp_connect_link_info_t *this_link_info = kn_link->transport_link;
	sctp_listen_link_info_t *info = this_link_info->listener;
	return info->listen_sock;
}
#endif
