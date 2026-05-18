/*
 * Copyright (C) 2017-2026 Red Hat, Inc.  All rights reserved.
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
	int logfd;
	struct sockaddr_storage out_addr;
	struct sockaddr_in *out_addrv4 = (struct sockaddr_in *)&out_addr;
	struct sockaddr_in6 *out_addrv6 = (struct sockaddr_in6 *)&out_addr;
	struct sockaddr_in addrv4;
	struct sockaddr_in6 addrv6;

	logfd = start_logging(stdout);

	memset(&out_addr, 0, sizeof(struct sockaddr_storage));
	memset(&addrv4, 0, sizeof(struct sockaddr_in));
	memset(&addrv6, 0, sizeof(struct sockaddr_in6));

	log_test(logfd, "Checking knet_strtoaddr with invalid host");

	if (!knet_strtoaddr(NULL, "50000", &out_addr, sizeof(struct sockaddr_storage)) ||
	    (errno != EINVAL)) {
		log_test(logfd, "knet_strtoaddr accepted invalid host or returned incorrect error: %s", strerror(errno));
		stop_logging();
		exit(FAIL);
	}

	log_test(logfd, "Checking knet_strtoaddr with invalid port");

	if (!knet_strtoaddr("127.0.0.1", NULL, &out_addr, sizeof(struct sockaddr_storage)) ||
	    (errno != EINVAL)) {
		log_test(logfd, "knet_strtoaddr accepted invalid port or returned incorrect error: %s", strerror(errno));
		stop_logging();
		exit(FAIL);
	}

	log_test(logfd, "Checking knet_strtoaddr with invalid addr");

	if (!knet_strtoaddr("127.0.0.1", "50000", NULL, sizeof(struct sockaddr_storage)) ||
	    (errno != EINVAL)) {
		log_test(logfd, "knet_strtoaddr accepted invalid addr or returned incorrect error: %s", strerror(errno));
		stop_logging();
		exit(FAIL);
	}

	log_test(logfd, "Checking knet_strtoaddr with invalid size");

	if (!knet_strtoaddr("127.0.0.1", "50000", &out_addr, 0) ||
	    (errno != EINVAL)) {
		log_test(logfd, "knet_strtoaddr accepted invalid size or returned incorrect error: %s", strerror(errno));
		stop_logging();
		exit(FAIL);
	}

	addrv4.sin_family = AF_INET;
	addrv4.sin_addr.s_addr = htonl(0xc0a80001); /* 192.168.0.1 */
	addrv4.sin_port = htons(50000);

	log_test(logfd, "Checking knet_strtoaddr with valid data (192.168.0.1:50000)");

	if (knet_strtoaddr("192.168.0.1", "50000", &out_addr, sizeof(struct sockaddr_storage))) {
		log_test(logfd, "Unable to convert 192.168.0.1:50000");
		stop_logging();
		exit(FAIL);
	}

	if (out_addrv4->sin_family != addrv4.sin_family ||
	    out_addrv4->sin_port != addrv4.sin_port ||
	    out_addrv4->sin_addr.s_addr != addrv4.sin_addr.s_addr) {
		log_test(logfd, "Check on 192.168.0.1:50000 failed");
		stop_logging();
		exit(FAIL);
	}

	log_test(logfd, "Checking knet_strtoaddr with valid data ([fd00::1]:50000)");

	memset(&out_addr, 0, sizeof(struct sockaddr_storage));

	addrv6.sin6_family = AF_INET6;
	addrv6.sin6_addr.s6_addr32[0] = htonl(0xfd000000); /* fd00::1 */
	addrv6.sin6_addr.s6_addr32[3] = htonl(0x00000001);
	addrv6.sin6_port = htons(50000);

	if (knet_strtoaddr("fd00::1", "50000", &out_addr, sizeof(struct sockaddr_storage))) {
		log_test(logfd, "Unable to convert fd00::1:50000");
		stop_logging();
		exit(FAIL);
	}

	if (out_addrv6->sin6_family != addrv6.sin6_family ||
	    out_addrv6->sin6_port != addrv6.sin6_port ||
	    memcmp(&out_addrv6->sin6_addr, &addrv6.sin6_addr, sizeof(struct in6_addr))) {

		log_test(logfd, "Check on fd00::1:50000 failed");
		stop_logging();
		exit(FAIL);
	}


	stop_logging();
}

int main(int argc, char *argv[])
{

	test();

	exit(PASS);
}
