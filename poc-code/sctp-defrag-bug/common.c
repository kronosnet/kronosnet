#include "config.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <zlib.h>

#ifdef HAVE_NETINET_SCTP_H
#include <netinet/sctp.h>
#include "common.h"

int strtoaddr(const char *host, const char *port, struct sockaddr_storage *ss, socklen_t sslen)
{
	int err;
	struct addrinfo hints;
	struct addrinfo *result = NULL;

	if (!host) {
		errno = EINVAL;
		return -1;
	}

	if (!port) {
		errno = EINVAL;
		return -1;
	}

	if (!ss) {
		errno = EINVAL;
		return -1;
	}

	if (!sslen) {
		errno = EINVAL;
		return -1;
	}

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	err = getaddrinfo(host, port, &hints, &result);

	if (!err) {
		memmove(ss, result->ai_addr,
			(sslen < result->ai_addrlen) ? sslen : result->ai_addrlen);

		freeaddrinfo(result);
	}

	return err;
}

int _fdset_cloexec(int fd)
{
	int fdflags;

	fdflags = fcntl(fd, F_GETFD, 0);
	if (fdflags < 0)
		return -1;

	fdflags |= FD_CLOEXEC;

	if (fcntl(fd, F_SETFD, fdflags) < 0)
		return -1;

	return 0;
}

int _fdset_nonblock(int fd)
{
	int fdflags;

	fdflags = fcntl(fd, F_GETFL, 0);
	if (fdflags < 0)
		return -1;

	fdflags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, fdflags) < 0)
		return -1;

	return 0;
}

int setup_sctp_common_sock_opts(int sock, struct sockaddr_storage *ss)
{
	struct sctp_event_subscribe events;
	int value;

	if (_fdset_cloexec(sock)) {
		fprintf(stderr, "unable to set CLOEXEC socket opts (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	if (_fdset_nonblock(sock)) {
		fprintf(stderr, "unable to set NONBLOCK socket opts (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	value = 8388608;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value)) < 0) {
		fprintf(stderr, "Unable to set receive buffer (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	value = 8388608;
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &value, sizeof(value)) < 0) {
		fprintf(stderr, "Unable to set send buffer (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	if (ss->ss_family == AF_INET6) {
		value = IPV6_PMTUDISC_PROBE;
		if (setsockopt(sock, SOL_IPV6, IPV6_MTU_DISCOVER, &value, sizeof(value)) <0) {
			fprintf(stderr, "Unable to set PMTUDISC (%d): %s\n",
				errno, strerror(errno));
			return -1;
		}
	} else {
		value = IP_PMTUDISC_PROBE;
		if (setsockopt(sock, SOL_IP, IP_MTU_DISCOVER, &value, sizeof(value)) <0) {
			fprintf(stderr, "Unable to set PMTUDISC (%d): %s\n",
				errno, strerror(errno));
			return -1;
		}
	}

	value = 1;
	if (setsockopt(sock, SOL_SCTP, SCTP_NODELAY, &value, sizeof(value)) < 0) {
		fprintf(stderr, "Unable to set SCTP_NODELAY (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

#if 0	/* workaround */
	value = 1;
	if (setsockopt(sock, SOL_SCTP, SCTP_DISABLE_FRAGMENTS, &value, sizeof(value)) < 0) {
		fprintf(stderr, "Unable to set SCTP_DISABLE_FRAGMENTS (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}
#endif

	memset(&events, 0, sizeof (events));
	events.sctp_data_io_event = 1;
	events.sctp_association_event = 1;
	events.sctp_send_failure_event = 1;
	events.sctp_address_event = 1;
	events.sctp_peer_error_event = 1;
	events.sctp_shutdown_event = 1;
        if (setsockopt(sock, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof (events)) < 0) {
		fprintf(stderr, "Unable to configure SCTP notifications (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	return 0;
}

int setup_sctp_server_sock_opts(int sock, struct sockaddr_storage *ss)
{
	int value;

	if (setup_sctp_common_sock_opts(sock, ss) < 0) {
		return -1;
	}

	value = 1;
	if (setsockopt(sock, SOL_IP, IP_FREEBIND, &value, sizeof(value)) <0) {
		fprintf(stderr, "Unable to set FREEBIND (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	if (ss->ss_family == AF_INET6) {
		value = 1;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
			       &value, sizeof(value)) < 0) {
			fprintf(stderr, "Unable to set IPv6 only (%d): %s\n",
				errno, strerror(errno));
			return -1;
		}
	}

	value = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0) {
		fprintf(stderr, "Unable to set REUSEADDR (%d): %s\n",
			errno, strerror(errno));
		return -1;
	}

	return 0;
}

static int fragsize = 0;

static void parse_incoming_data(struct mmsghdr msg, int check_crc)
{
	int i;
	struct iovec *iov = msg.msg_hdr.msg_iov;
	size_t iovlen = msg.msg_hdr.msg_iovlen;
	unsigned int crc;
	unsigned int *data = msg.msg_hdr.msg_iov->iov_base;
	size_t datalen = msg.msg_len;
	union sctp_notification  *snp;

	if (!(msg.msg_hdr.msg_flags & MSG_NOTIFICATION)) {
		if (msg.msg_len == 0) {
			fprintf(stderr, "Received 0bytes packet\n");
			exit(-1);
		}
		if (!(msg.msg_hdr.msg_flags & MSG_EOR)) {
			fprintf(stderr, "got a fragment size: %d\n", msg.msg_len);
			fragsize = fragsize + msg.msg_len;
			return;
		}
		if (fragsize) {
			fragsize = fragsize + msg.msg_len;
			fprintf(stderr, "Received all packets from frags: %d\n", fragsize);
			if (fragsize != 65536) {
				fprintf(stderr, "KABOOM: %d\n", msg.msg_len);
				exit(-1);
			}
			fragsize = 0;
		} else {
			/* check pckt len here */
			if (msg.msg_len != 65536) {
				fprintf(stderr, "KABOOM: %d\n", msg.msg_len);
				exit(-1);
			}
			if (check_crc) {
				crc = crc32(0, NULL, 0);
				crc = crc32(crc, (Bytef *)&data[1], datalen - sizeof(unsigned int)) & 0xFFFFFFFF;
				if (crc != data[0]) {
					fprintf(stderr, "KABOOM - CRCs do not match\n");
					exit(-1);
				}
			}
		}
		return;
	}

	if (!(msg.msg_hdr.msg_flags & MSG_EOR)) {
		fprintf(stderr, "[event] end of notifications\n");
		return;
	}

	/* got a notification */
	for (i=0; i< iovlen; i++) {
		snp = iov[i].iov_base;

		switch (snp->sn_header.sn_type) {
			case SCTP_ASSOC_CHANGE:
				fprintf(stderr, "[event] sctp assoc change\n");
				break;
			case SCTP_SHUTDOWN_EVENT:
				fprintf(stderr, "[event] sctp shutdown event\n");
				break;
			case SCTP_SEND_FAILED:
				fprintf(stderr, "[event] sctp send failed\n");
				break;
			case SCTP_PEER_ADDR_CHANGE:
				fprintf(stderr, "[event] sctp peer addr change\n");
				break;
			case SCTP_REMOTE_ERROR:
				fprintf(stderr, "[event] sctp remote error\n");
				break;
			default:
				fprintf(stderr, "[event] unknown sctp event type: %hu\n", snp->sn_header.sn_type);
				exit(-1);
				break;
		}
	}
	return;
}

void get_incoming_data(int sock, struct mmsghdr *msg, int check_crc)
{
	int i, msg_recv;

	msg_recv = recvmmsg(sock, msg, 256, MSG_DONTWAIT | MSG_NOSIGNAL, NULL);

	if (msg_recv <= 0) {
		fprintf(stderr, "Error message received from recvmmsg (%d): %s\n",
			errno, strerror(errno));
		exit(-1);
	}

	fprintf(stderr, "Received: %d messages\n", msg_recv);

	for (i = 0; i < msg_recv; i++) {
		parse_incoming_data(msg[i], check_crc);
	}
}

int setup_rx_buffers(struct mmsghdr *msg)
{
	int i;
	struct sockaddr_storage addr[256];
	struct iovec iov_in[256];

	if (!msg) {
		return -1;
	}

	/*
	 * Setup buffers
	 */
	for (i = 0; i < 256; i++) {
		iov_in[i].iov_base = (void *)malloc(65536);
		if (!iov_in[i].iov_base) {
			fprintf(stderr, "Unable to malloc RX buffers(%d): %s\n",
				errno, strerror(errno));
			return -1;
		}
		memset(iov_in[i].iov_base, 0, 65536);
		iov_in[i].iov_len = 65536;
		memset(&msg[i].msg_hdr, 0, sizeof(struct msghdr));
		msg[i].msg_hdr.msg_name = &addr[i];
		msg[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
		msg[i].msg_hdr.msg_iov = &iov_in[i];
		msg[i].msg_hdr.msg_iovlen = 1;
	}
	return 0;
}
#endif
