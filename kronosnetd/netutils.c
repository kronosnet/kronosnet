/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
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

#include "netutils.h"

#define ADDRTOSTR_HOST_LEN 256
#define ADDRTOSTR_PORT_LEN 24

static int is_v4_mapped(struct sockaddr_storage *ss, socklen_t salen)
{
	char map[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) ss;
	return memcmp(&addr6->sin6_addr, map, 12);
}

/*
 * unused now - move to libknet for ACL
 */

int cmpaddr(struct sockaddr_storage *ss1, socklen_t sslen1,
	    struct sockaddr_storage *ss2, socklen_t sslen2)
{
	int ss1_offset = 0, ss2_offset = 0;
	struct sockaddr_in6 *ss1_addr6 = (struct sockaddr_in6 *)ss1;
	struct sockaddr_in6 *ss2_addr6 = (struct sockaddr_in6 *)ss2;
	struct sockaddr_in *ss1_addr = (struct sockaddr_in *)ss1;
	struct sockaddr_in *ss2_addr = (struct sockaddr_in *)ss2;
	char *addr1, *addr2;

	if (ss1->ss_family == ss2->ss_family)
		return memcmp(ss1, ss2, sslen1);

	if (ss1->ss_family == AF_INET6) {
		if (is_v4_mapped(ss1, sslen1))
			return 1;

		addr1 = (char *)&ss1_addr6->sin6_addr;
		ss1_offset = 12;
	} else
		addr1 = (char *)&ss1_addr->sin_addr;

	if (ss2->ss_family == AF_INET6) {
		if (is_v4_mapped(ss2, sslen2))
			return 1;

		addr2 = (char *)&ss2_addr6->sin6_addr;  
		ss2_offset = 12;
	} else
		addr2 = (char *)&ss2_addr->sin_addr; 

	return memcmp(addr1+ss1_offset, addr2+ss2_offset, 4);
}

int strtoaddr(const char *host, const char *port, struct sockaddr *sa, socklen_t salen)
{
	int ret;
	struct addrinfo hints;
	struct addrinfo *result = NULL;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	ret = getaddrinfo(host, port, &hints, &result);

	if (ret != 0) {
		errno = EINVAL;
		return -1;
	}

	memmove(sa, result->ai_addr,
		(salen < result->ai_addrlen) ? salen : result->ai_addrlen);

	freeaddrinfo(result);

	return ret;
}

int addrtostr(const struct sockaddr *sa, socklen_t salen, char *buf[2])
{
	int ret;

	buf[0] = malloc(ADDRTOSTR_HOST_LEN + ADDRTOSTR_PORT_LEN);

	if (buf[0] == NULL)
		return -1;

	buf[1] = buf[0] + ADDRTOSTR_HOST_LEN;

	ret = getnameinfo(sa, salen, buf[0], ADDRTOSTR_HOST_LEN,
				buf[1], ADDRTOSTR_PORT_LEN,
				NI_NUMERICHOST | NI_NUMERICSERV);

	if (ret != 0) {
		buf[0] = '\0';
		buf[1] = '\0';
	} else {
		buf[0][ADDRTOSTR_HOST_LEN - 1] = '\0';
		buf[1][ADDRTOSTR_PORT_LEN - 1] = '\0';
	}

	return ret;
}

void addrtostr_free(char *str[2])
{
	if (str[0] != NULL)
		free(str[0]);
}
