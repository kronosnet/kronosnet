/*
 * Copyright (C) 2010-2021 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
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

int cmpaddr(const struct sockaddr_storage *ss1, const struct sockaddr_storage *ss2)
{
	struct sockaddr_in6 *ss1_addr6 = (struct sockaddr_in6 *)ss1;
	struct sockaddr_in6 *ss2_addr6 = (struct sockaddr_in6 *)ss2;
	struct sockaddr_in *ss1_addr = (struct sockaddr_in *)ss1;
	struct sockaddr_in *ss2_addr = (struct sockaddr_in *)ss2;

	if (ss1->ss_family != ss2->ss_family) {
		return -1;
	}

	if (ss1->ss_family == AF_INET6) {
		return memcmp(&ss1_addr6->sin6_addr.s6_addr32, &ss2_addr6->sin6_addr.s6_addr32, sizeof(struct in6_addr));
	}

	return memcmp(&ss1_addr->sin_addr.s_addr, &ss2_addr->sin_addr.s_addr, sizeof(struct in_addr));
}

socklen_t sockaddr_len(const struct sockaddr_storage *ss)
{
        if (ss->ss_family == AF_INET) {
	        return sizeof(struct sockaddr_in);
	} else {
	        return sizeof(struct sockaddr_in6);
	}
}

/* Only copy the valid parts of a sockaddr* */
void copy_sockaddr(struct sockaddr_storage *sout, const struct sockaddr_storage *sin)
{
	memset(sout, 0, sizeof(struct sockaddr_storage));
	memmove(sout, sin, sockaddr_len(sin));
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

	if (!err)
		errno = 0;
	return err;
}

int knet_addrtostr(const struct sockaddr_storage *ss, socklen_t sslen,
		   char *addr_buf, size_t addr_buf_size,
		   char *port_buf, size_t port_buf_size)
{
	int err;

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

	err = getnameinfo((struct sockaddr *)ss, sockaddr_len(ss),
			  addr_buf, addr_buf_size,
			  port_buf, port_buf_size,
			  NI_NUMERICHOST | NI_NUMERICSERV);

	if (!err)
		errno = 0;
	return err;
}
