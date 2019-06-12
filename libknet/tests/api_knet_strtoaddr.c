/*
 * Copyright (C) 2017-2019 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "libknet.h"
#include "test-common.h"

static void test(void)
{
	struct sockaddr_storage out_addr;
	struct sockaddr_in *out_addrv4 = (struct sockaddr_in *)&out_addr;
	struct sockaddr_in6 *out_addrv6 = (struct sockaddr_in6 *)&out_addr;
	struct sockaddr_in addrv4;
	struct sockaddr_in6 addrv6;

	memset(&out_addr, 0, sizeof(struct sockaddr_storage));
	memset(&addrv4, 0, sizeof(struct sockaddr_in));
	memset(&addrv6, 0, sizeof(struct sockaddr_in6));

	printf("Checking knet_strtoaddr with invalid host\n");

	if (!knet_strtoaddr(NULL, "50000", &out_addr, sizeof(struct sockaddr_storage)) ||
	    (errno != EINVAL)) {
		printf("knet_strtoaddr accepted invalid host or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Checking knet_strtoaddr with invalid port\n");

	if (!knet_strtoaddr("127.0.0.1", NULL, &out_addr, sizeof(struct sockaddr_storage)) ||
	    (errno != EINVAL)) {
		printf("knet_strtoaddr accepted invalid port or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Checking knet_strtoaddr with invalid addr\n");

	if (!knet_strtoaddr("127.0.0.1", "50000", NULL, sizeof(struct sockaddr_storage)) ||
	    (errno != EINVAL)) {
		printf("knet_strtoaddr accepted invalid addr or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Checking knet_strtoaddr with invalid size\n");

	if (!knet_strtoaddr("127.0.0.1", "50000", &out_addr, 0) ||
	    (errno != EINVAL)) {
		printf("knet_strtoaddr accepted invalid size or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	addrv4.sin_family = AF_INET;
	addrv4.sin_addr.s_addr = htonl(0xc0a80001); /* 192.168.0.1 */
	addrv4.sin_port = htons(50000);

	printf("Checking knet_strtoaddr with valid data (192.168.0.1:50000)\n");

	if (knet_strtoaddr("192.168.0.1", "50000", &out_addr, sizeof(struct sockaddr_storage))) {
		printf("Unable to convert 192.168.0.1:50000\n");
		exit(FAIL);
	}

	if (out_addrv4->sin_family != addrv4.sin_family ||
	    out_addrv4->sin_port != addrv4.sin_port ||
	    out_addrv4->sin_addr.s_addr != addrv4.sin_addr.s_addr) {
		printf("Check on 192.168.0.1:50000 failed\n");
		exit(FAIL);
	}

	printf("Checking knet_strtoaddr with valid data ([fd00::1]:50000)\n");

	memset(&out_addr, 0, sizeof(struct sockaddr_storage));

	addrv6.sin6_family = AF_INET6;
	addrv6.sin6_addr.s6_addr16[0] = htons(0xfd00); /* fd00::1 */
	addrv6.sin6_addr.s6_addr16[7] = htons(0x0001);
	addrv6.sin6_port = htons(50000);

	if (knet_strtoaddr("fd00::1", "50000", &out_addr, sizeof(struct sockaddr_storage))) {
		printf("Unable to convert fd00::1:50000\n");
		exit(FAIL);
	}

	if (out_addrv6->sin6_family != addrv6.sin6_family ||
	    out_addrv6->sin6_port != addrv6.sin6_port ||
	    memcmp(&out_addrv6->sin6_addr, &addrv6.sin6_addr, sizeof(struct in6_addr))) {

		printf("Check on fd00::1:50000 failed\n");
		exit(FAIL);
	}

}

int main(int argc, char *argv[])
{

	test();

	exit(PASS);
}
