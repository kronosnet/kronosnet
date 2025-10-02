/*
 * Copyright (C) 2016-2025 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/uio.h>

#include "libknet.h"
#include "compat.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "common.h"
#include "transport_common.h"

/*
 * reuse Jan Friesse's compat layer as wrapper to drop usage of sendmmsg
 *
 * TODO: kill those wrappers once we work on packet delivery guarantees
 */

int _recvmmsg(int sockfd, struct knet_mmsghdr *msgvec, unsigned int vlen, unsigned int flags)
{
	int savederrno = 0, err = 0;
	unsigned int i;

	for (i = 0; i < vlen; i++) {
		err = recvmsg(sockfd, &msgvec[i].msg_hdr, flags);
		savederrno = errno;
		if (err >= 0) {
			msgvec[i].msg_len = err;
			if (err == 0) {
				/* No point in reading anything more until we know this has been dealt with
				   or we'll just get a vector full of them. Several in fact */
				i++;
				break;
			}
		} else {
			if ((i > 0) &&
			    ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
				savederrno = 0;
			}
			break;
		}
	}

	errno = savederrno;
	return ((i > 0) ? (int)i : err);
}

int _sendmmsg(int sockfd, int connection_oriented, struct knet_mmsghdr *msgvec, unsigned int vlen, unsigned int flags)
{
	int savederrno = 0, err = 0;
	unsigned int i;
	struct msghdr temp_msg;
	struct msghdr *use_msghdr;

	for (i = 0; i < vlen; i++) {
		if (connection_oriented == TRANSPORT_PROTO_IS_CONNECTION_ORIENTED) {
			memcpy(&temp_msg, &msgvec[i].msg_hdr, sizeof(struct msghdr));
			temp_msg.msg_name = NULL;
			temp_msg.msg_namelen = 0;
			use_msghdr = &temp_msg;
		} else {
			use_msghdr = &msgvec[i].msg_hdr;
		}
		err = sendmsg(sockfd, use_msghdr, flags);
		savederrno = errno;
		if (err < 0) {
			break;
		}
	}

	errno = savederrno;
	return ((i > 0) ? (int)i : err);
}

/* Assume neither of these constants can ever be zero */
#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE 0
#endif
#ifndef SO_SNDBUFFORCE
#define SO_SNDBUFFORCE 0
#endif

static int _configure_sockbuf(knet_handle_t knet_h, int sock, int option, int force, int target)
{
	int savederrno = 0;
	int new_value;
	socklen_t value_len = sizeof new_value;

	if (setsockopt(sock, SOL_SOCKET, option, &target, sizeof target) != 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_TRANSPORT,
			"Error setting socket buffer via option %d to value %d: %s\n",
			option, target, strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (getsockopt(sock, SOL_SOCKET, option, &new_value, &value_len) != 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_TRANSPORT,
			"Error getting socket buffer via option %d: %s\n",
			option, strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (value_len != sizeof new_value) {
		log_err(knet_h, KNET_SUB_TRANSPORT,
			"Socket option %d returned unexpected size %u\n",
			option, value_len);
		errno = ERANGE;
		return -1;
	}

	if (target <= new_value) {
		return 0;
	}

	if (!force || !(knet_h->flags & KNET_HANDLE_FLAG_PRIVILEGED)) {
		log_err(knet_h, KNET_SUB_TRANSPORT,
			"Failed to set socket buffer via option %d to value %d: capped at %d",
			option, target, new_value);
		if (!(knet_h->flags & KNET_HANDLE_FLAG_PRIVILEGED)) {
			log_err(knet_h, KNET_SUB_TRANSPORT,
				"Continuing regardless, as the handle is not privileged."
				" Expect poor performance!");
			return 0;
		} else {
			errno = ENAMETOOLONG;
			return -1;
		}
	}

	if (setsockopt(sock, SOL_SOCKET, force, &target, sizeof target) < 0) {
		savederrno = errno;
		log_err(knet_h, KNET_SUB_TRANSPORT,
			"Failed to set socket buffer via force option %d: %s",
			force, strerror(savederrno));
		if (savederrno == EPERM) {
			errno = ENAMETOOLONG;
		} else {
			errno = savederrno;
		}
		return -1;
	}

	return 0;
}

int _configure_common_socket(knet_handle_t knet_h, int sock, uint64_t flags, const char *type)
{
	int err = 0, savederrno = 0;

	if (_fdset_cloexec(sock)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set %s CLOEXEC socket opts: %s",
			type, strerror(savederrno));
		goto exit_error;
	}

	if (_fdset_nonblock(sock)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set %s NONBLOCK socket opts: %s",
			type, strerror(savederrno));
		goto exit_error;
	}

	if (_configure_sockbuf(knet_h, sock, SO_RCVBUF, SO_RCVBUFFORCE, KNET_RING_RCVBUFF)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set %s receive buffer: %s",
			type, strerror(savederrno));
		goto exit_error;
	}

	if (_configure_sockbuf(knet_h, sock, SO_SNDBUF, SO_SNDBUFFORCE, KNET_RING_RCVBUFF)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set %s send buffer: %s",
			type, strerror(savederrno));
		goto exit_error;
	}

	if (flags & KNET_LINK_FLAG_TRAFFICHIPRIO) {
#ifdef KNET_LINUX
#ifdef SO_PRIORITY
		int value = 6; /* TC_PRIO_INTERACTIVE */

		if (setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &value, sizeof(value)) < 0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set %s priority: %s",
				type, strerror(savederrno));
			goto exit_error;
		}
		log_debug(knet_h, KNET_SUB_TRANSPORT, "TC_PRIO_INTERACTIVE enabled on socket: %i", sock);
#else
		log_debug(knet_h, KNET_SUB_TRANSPORT, "TC_PRIO_INTERACTIVE not available in this build/platform");
#endif
#endif
#if defined(IP_TOS)
		if (knet_h->prio_dscp) {
			/* dscp is the 6 highest bits of TOS IP header field, RFC 2474 */
			int value = (knet_h->prio_dscp & 0x3f) << 2;

			if (setsockopt(sock, IPPROTO_IP, IP_TOS, &value, sizeof(value)) < 0) {
				savederrno = errno;
				err = -1;
				log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set %s priority: %s",
					type, strerror(savederrno));
				goto exit_error;
			}
			log_debug(knet_h, KNET_SUB_TRANSPORT, "dscp %d set on socket: %i", knet_h->prio_dscp, sock);
		} else {
#if defined(IPTOS_LOWDELAY)
			int value = IPTOS_LOWDELAY;

			if (setsockopt(sock, IPPROTO_IP, IP_TOS, &value, sizeof(value)) < 0) {
				savederrno = errno;
				err = -1;
				log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set %s priority: %s",
					type, strerror(savederrno));
				goto exit_error;
			}
			log_debug(knet_h, KNET_SUB_TRANSPORT, "IPTOS_LOWDELAY enabled on socket: %i", sock);
#else
			log_debug(knet_h, KNET_SUB_TRANSPORT, "IPTOS_LOWDELAY not available in this build/platform");
#endif
		}
#endif
	}

exit_error:
	errno = savederrno;
	return err;
}

int _configure_transport_socket(knet_handle_t knet_h, int sock, struct sockaddr_storage *address, uint64_t flags, const char *type)
{
	int err = 0, savederrno = 0;
	int value;

	if (_configure_common_socket(knet_h, sock, flags, type) < 0) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

#ifdef KNET_LINUX
#ifdef IP_FREEBIND
	value = 1;
	if (setsockopt(sock, SOL_IP, IP_FREEBIND, &value, sizeof(value)) <0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set FREEBIND on %s socket: %s",
			type, strerror(savederrno));
		goto exit_error;
	}
	log_debug(knet_h, KNET_SUB_TRANSPORT, "FREEBIND enabled on socket: %i", sock);
#else
	log_debug(knet_h, KNET_SUB_TRANSPORT, "FREEBIND not available in this build/platform");
#endif
#endif
#ifdef KNET_BSD
#ifdef IP_BINDANY /* BSD */
	value = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_BINDANY, &value, sizeof(value)) <0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set BINDANY on %s socket: %s",
			type, strerror(savederrno));
		goto exit_error;
	}
	log_debug(knet_h, KNET_SUB_TRANSPORT, "BINDANY enabled on socket: %i", sock);
#else
	log_debug(knet_h, KNET_SUB_TRANSPORT, "BINDANY not available in this build/platform");
#endif
#endif

	if (address->ss_family == AF_INET6) {
		value = 1;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
			       &value, sizeof(value)) < 0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set %s IPv6 only: %s",
				type, strerror(savederrno));
			goto exit_error;

		}
#ifdef KNET_LINUX
#ifdef IPV6_MTU_DISCOVER
		value = IPV6_PMTUDISC_PROBE;
		if (setsockopt(sock, SOL_IPV6, IPV6_MTU_DISCOVER, &value, sizeof(value)) <0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set PMTUDISC on %s socket: %s",
				type, strerror(savederrno));
			goto exit_error;
		}
		log_debug(knet_h, KNET_SUB_TRANSPORT, "IPV6_MTU_DISCOVER enabled on socket: %i", sock);
#else
		log_debug(knet_h, KNET_SUB_TRANSPORT, "IPV6_MTU_DISCOVER not available in this build/platform");
#endif
#endif
#ifdef IPV6_DONTFRAG
		value = 1;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_DONTFRAG, &value, sizeof(value)) <0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set DONTFRAG on %s socket: %s",
				type, strerror(savederrno));
			goto exit_error;
		}
		log_debug(knet_h, KNET_SUB_TRANSPORT, "IPV6_DONTFRAG enabled on socket: %i", sock);
#else
		log_debug(knet_h, KNET_SUB_TRANSPORT, "IPV6_DONTFRAG not available in this build/platform");
#endif
	} else {
#ifdef KNET_LINUX
#ifdef IP_MTU_DISCOVER
		value = IP_PMTUDISC_PROBE;
		if (setsockopt(sock, SOL_IP, IP_MTU_DISCOVER, &value, sizeof(value)) <0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set PMTUDISC on %s socket: %s",
				type, strerror(savederrno));
			goto exit_error;
		}
		log_debug(knet_h, KNET_SUB_TRANSPORT, "PMTUDISC enabled on socket: %i", sock);
#else
		log_debug(knet_h, KNET_SUB_TRANSPORT, "PMTUDISC not available in this build/platform");
#endif
#endif
#if defined(KNET_BSD) || defined(KNET_SOLARIS)
#ifdef IP_DONTFRAG
		value = 1;
		if (setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, &value, sizeof(value)) <0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set DONTFRAG on %s socket: %s",
				type, strerror(savederrno));
			goto exit_error;
		}
		log_debug(knet_h, KNET_SUB_TRANSPORT, "DONTFRAG enabled on socket: %i", sock);
#else
		log_debug(knet_h, KNET_SUB_TRANSPORT, "DONTFRAG not available in this build/platform");
#endif
#endif
	}

exit_error:
	errno = savederrno;
	return err;
}

int _init_socketpair(knet_handle_t knet_h, int *sock)
{
	int err = 0, savederrno = 0;
	int i;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sock) != 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to initialize socketpair: %s",
			strerror(savederrno));
		goto exit_fail;
	}

	for (i = 0; i < 2; i++) {
		if (_configure_common_socket(knet_h, sock[i], 0, "local socketpair") < 0) {
			savederrno = errno;
			err = -1;
			goto exit_fail;
		}
	}

exit_fail:
	errno = savederrno;
	return err;
}

void _close_socketpair(knet_handle_t knet_h, int *sock)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (sock[i]) {
			close(sock[i]);
			sock[i] = 0;
		}
	}
}

/*
 * must be called with global read lock
 *
 * return -1 on error
 * return 0 if fd is invalid
 * return 1 if fd is valid
 */
int _is_valid_fd(knet_handle_t knet_h, int sockfd)
{
	int ret = 0;

	if (sockfd < 0) {
		errno = EINVAL;
		return -1;
	}

	if (sockfd >= KNET_MAX_FDS) {
		errno = EINVAL;
		return -1;
	}

	if (knet_h->knet_transport_fd_tracker[sockfd].transport >= KNET_MAX_TRANSPORTS) {
		ret = 0;
	} else {
		ret = 1;
	}

	return ret;
}

/*
 * must be called with global write lock
 */

int _set_fd_tracker(knet_handle_t knet_h, int sockfd, uint8_t transport, uint8_t data_type, socklen_t socklen, void *data, int ifindex)
{
	if (sockfd < 0) {
		errno = EINVAL;
		return -1;
	}

	if (sockfd >= KNET_MAX_FDS) {
		errno = EINVAL;
		return -1;
	}

	knet_h->knet_transport_fd_tracker[sockfd].transport = transport;
	knet_h->knet_transport_fd_tracker[sockfd].data_type = data_type;
	knet_h->knet_transport_fd_tracker[sockfd].sockaddr_len = socklen;
	knet_h->knet_transport_fd_tracker[sockfd].data = data;
	knet_h->knet_transport_fd_tracker[sockfd].ifindex = ifindex;

	return 0;
}

/*
 * Wrapper function for writev that retries until all data is written.
 */
ssize_t writev_all(knet_handle_t knet_h, int fd, struct iovec *iov, int iovcnt, struct knet_link *local_link, uint8_t log_subsys)
{
	ssize_t total_written = 0; /* Total bytes written */
	ssize_t written; /* Bytes written by single writev */
	int iov_index = 0;

	for (;;) {
		written = writev(fd, iov, iovcnt);

		if (written < 0) {
			/* retry on signal */
			if (errno == EINTR) {
				continue;
			}
			/* Other errors */
			return -1;
		}

		total_written += written;

		while ((size_t)written >= iov[iov_index].iov_len) {
			written -= iov[iov_index].iov_len;
			iov_index++;
			if (iov_index >= iovcnt) {
				/* Everything written */
				goto out;
			}
		}

		iov[iov_index].iov_base = (char *)iov[iov_index].iov_base + written;
		iov[iov_index].iov_len -= written;

		if (local_link != NULL) {
			local_link->status.stats.tx_data_retries++;
		}
	}

out:
	// coverity[INTEGER_OVERFLOW:SUPPRESS] - it hasn't overflowed, really.
	return total_written;
}
