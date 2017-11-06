/*
 * Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>

#include "internals.h"
#include "netutils.h"

static int is_v4_mapped(const struct sockaddr_storage *ss, socklen_t salen)
{
	char map[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) ss;
	return memcmp(&addr6->sin6_addr, map, 12);
}

int cmpaddr(const struct sockaddr_storage *ss1, socklen_t sslen1,
	    const struct sockaddr_storage *ss2, socklen_t sslen2)
{
	int ss1_offset = 0, ss2_offset = 0;
	struct sockaddr_in6 *ss1_addr6 = (struct sockaddr_in6 *)ss1;
	struct sockaddr_in6 *ss2_addr6 = (struct sockaddr_in6 *)ss2;
	struct sockaddr_in *ss1_addr = (struct sockaddr_in *)ss1;
	struct sockaddr_in *ss2_addr = (struct sockaddr_in *)ss2;
	char *addr1, *addr2;

	if (ss1->ss_family == ss2->ss_family) {
		return memcmp(ss1, ss2, sslen1);
	}

	if (ss1->ss_family == AF_INET6) {
		if (is_v4_mapped(ss1, sslen1)) {
			return 1;
		}
		addr1 = (char *)&ss1_addr6->sin6_addr;
		ss1_offset = 12;
	} else {
		addr1 = (char *)&ss1_addr->sin_addr;
	}

	if (ss2->ss_family == AF_INET6) {
		if (is_v4_mapped(ss2, sslen2)) {
			return 1;
		}
		addr2 = (char *)&ss2_addr6->sin6_addr;
		ss2_offset = 12;
	} else {
		addr2 = (char *)&ss2_addr->sin_addr;
	}

	return memcmp(addr1+ss1_offset, addr2+ss2_offset, 4);
}

int cpyaddrport(struct sockaddr_storage *dst, const struct sockaddr_storage *src)
{
	struct sockaddr_in6 *dst_addr6 = (struct sockaddr_in6 *)dst;
	struct sockaddr_in6 *src_addr6 = (struct sockaddr_in6 *)src;

	memset(dst, 0, sizeof(struct sockaddr_storage));

	if (src->ss_family == AF_INET6) {
		dst->ss_family = src->ss_family;
		memmove(&dst_addr6->sin6_port, &src_addr6->sin6_port, sizeof(in_port_t));
		memmove(&dst_addr6->sin6_addr, &src_addr6->sin6_addr, sizeof(struct in6_addr));
	} else {
		memmove(dst, src, sizeof(struct sockaddr_in));
	}
	return 0;
}

socklen_t sockaddr_len(const struct sockaddr_storage *ss)
{
        if (ss->ss_family == AF_INET) {
	        return sizeof(struct sockaddr_in);
	} else {
	        return sizeof(struct sockaddr_in6);
	}
}

/*
 * exported APIs
 */

int knet_strtoaddr(const char *host, const char *port, struct sockaddr_storage *ss, socklen_t sslen)
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

int knet_addrtostr(const struct sockaddr_storage *ss, socklen_t sslen,
		   char *addr_buf, size_t addr_buf_size,
		   char *port_buf, size_t port_buf_size)
{
	if (!ss) {
		errno = EINVAL;
		return -1;
	}

	if (!sslen) {
		errno = EINVAL;
		return -1;
	}

	if (!addr_buf) {
		errno = EINVAL;
		return -1;
	}

	if (!port_buf) {
		errno = EINVAL;
		return -1;
	}

	return getnameinfo((struct sockaddr *)ss, sockaddr_len(ss), addr_buf, addr_buf_size,
				port_buf, port_buf_size,
				NI_NUMERICHOST | NI_NUMERICSERV);
}
