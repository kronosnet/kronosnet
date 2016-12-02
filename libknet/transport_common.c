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

#ifdef DEBUG
/*
 * Keeping this light (and there fornot thread-safe) as it's
 * for debugging only
 */
const char *_transport_print_ip(const struct sockaddr_storage *ss)
{
	static char printbuf[INET6_ADDRSTRLEN];

	if (ss->ss_family == AF_INET) {
		struct sockaddr_in *in4 = (struct sockaddr_in *)ss;
		return inet_ntop(AF_INET, &in4->sin_addr, printbuf, sizeof(printbuf));
	}
	else {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;
		return inet_ntop(AF_INET6, &in6->sin6_addr, printbuf, sizeof(printbuf));
	}
}
#else
const char *_transport_print_ip(const struct sockaddr_storage *ss)
{
	return "node";
}
#endif

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
