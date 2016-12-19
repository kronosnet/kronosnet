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
#include <arpa/inet.h>

#include "libknet.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "common.h"
#include "transports.h"
#include "../common/netutils.h"

int _configure_transport_socket(knet_handle_t knet_h, int sock, struct sockaddr_storage *address, const char *type)
{
	int err = 0;
	int value;
	int savederrno;

	value = KNET_RING_RCVBUFF;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT_T, "Unable to set %s receive buffer: %s",
			type, strerror(savederrno));
		goto exit_error;
	}

	value = KNET_RING_RCVBUFF;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &value, sizeof(value)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT_T, "Unable to set %s send buffer: %s",
			type, strerror(savederrno));
		goto exit_error;
	}

	value = 1;
	if (setsockopt(sock, SOL_IP, IP_FREEBIND, &value, sizeof(value)) <0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT_T, "Unable to set FREEBIND on %s socket: %s",
			type, strerror(savederrno));
		goto exit_error;
	}

	if (address->ss_family == AF_INET6) {
		value = 1;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
			       &value, sizeof(value)) < 0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSPORT_T, "Unable to set %s IPv6 only: %s",
				type, strerror(savederrno));
			goto exit_error;

		}
		value = IPV6_PMTUDISC_PROBE;
		if (setsockopt(sock, SOL_IPV6, IPV6_MTU_DISCOVER, &value, sizeof(value)) <0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSPORT_T, "Unable to set PMTUDISC on %s socket: %s",
				type, strerror(savederrno));
			goto exit_error;
		}
	} else {
		value = IP_PMTUDISC_PROBE;
		if (setsockopt(sock, SOL_IP, IP_MTU_DISCOVER, &value, sizeof(value)) <0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSPORT_T, "Unable to set PMTUDISC on %s socket: %s",
				type, strerror(savederrno));
			goto exit_error;
		}
	}

	value = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT_T, "Unable to set %s reuseaddr: %s",
			type, strerror(savederrno));
		goto exit_error;
	}

	if (_fdset_cloexec(sock)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT_T, "Unable to set %s CLOEXEC socket opts: %s",
			type, strerror(savederrno));
		goto exit_error;
	}

	if (_fdset_nonblock(sock)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT_T, "Unable to set %s NONBLOCK socket opts: %s",
			type, strerror(savederrno));
		goto exit_error;
	}

	err = 0;

exit_error:
	return err;
}

void _close_socket(knet_handle_t knet_h, int sockfd)
{
	struct epoll_event ev;
	int i;

	log_err(knet_h, KNET_SUB_LINK_T, "EOF received on socket fd %d", sockfd);

	memset(&ev, 0, sizeof(struct epoll_event));

	ev.events = EPOLLIN;
	ev.data.fd = sockfd;
	if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, sockfd, &ev)) {
		log_err(knet_h, KNET_SUB_LISTENER, "Unable to remove EOFed socket from epoll pool: %s",
			strerror(errno));
	}

	/* Tell transport that the FD has been closed */
	for (i=0; i<KNET_MAX_TRANSPORTS; i++) {
		if ((knet_h->transport_ops[i]) &&
		    (knet_h->transport_ops[i]->handle_fd_eof) &&
		    (!knet_h->transport_ops[i]->handle_fd_eof(knet_h, sockfd)))
			break;
	}
}

void _handle_socket_notification(knet_handle_t knet_h, int sockfd, struct iovec *iov, size_t iovlen)
{
	int i;

	/* Find the transport and post the message */
	for (i=0; i<KNET_MAX_TRANSPORTS; i++) {
		if ((knet_h->transport_ops[i]) &&
		    (knet_h->transport_ops[i]->handle_fd_notification) &&
		    (knet_h->transport_ops[i]->handle_fd_notification(knet_h, sockfd, iov, iovlen)))
			break;
	}
}

/*
 * Wrappers for addrtostr() & addrtostr_free() for use when we only need the IP address
 * printing in DEBUG mode - it's to heavy for within normal use
 */
int _transport_addrtostr(const struct sockaddr *sa, socklen_t salen, char *str[2])
{
#ifdef DEBUG
	return addrtostr(sa, salen, str);
#else
	str[0] = (char*)"node";
	str[1] = (char*)"";
	return 0;
#endif
}

void _transport_addrtostr_free(char *str[2])
{
#ifdef DEBUG
	addrtostr_free(str);
#else
#endif
}
