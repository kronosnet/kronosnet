/*
 * Copyright (C) 2017-2025 Red Hat, Inc.  All rights reserved.
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
	struct sockaddr_storage addr;
	struct sockaddr_in *addrv4;
	struct sockaddr_in6 *addrv6;
	char addr_str[KNET_MAX_HOST_LEN];
	char port_str[KNET_MAX_PORT_LEN];

	memset(&addr, 0, sizeof(struct sockaddr_storage));

	printf("Checking knet_addrtostr with invalid ss\n");

	if (!knet_addrtostr(NULL, sizeof(struct sockaddr_storage),
			    addr_str, KNET_MAX_HOST_LEN,
			    port_str, KNET_MAX_PORT_LEN) || (errno != EINVAL)) {
		printf("knet_addrtostr accepted invalid ss or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Checking knet_addrtostr with invalid sslen\n");

	if (!knet_addrtostr(&addr, 0,
			    addr_str, KNET_MAX_HOST_LEN,
			    port_str, KNET_MAX_PORT_LEN) || (errno != EINVAL)) {
		printf("knet_addrtostr accepted invalid sslen or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Checking knet_addrtostr with invalid addr_str\n");

	if (!knet_addrtostr(&addr, sizeof(struct sockaddr_storage),
			    NULL, KNET_MAX_HOST_LEN,
			    port_str, KNET_MAX_PORT_LEN) || (errno != EINVAL)) {
		printf("knet_addrtostr accepted invalid addr_str or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Checking knet_addrtostr with invalid port_str\n");

	if (!knet_addrtostr(&addr, sizeof(struct sockaddr_storage),
			    addr_str, KNET_MAX_HOST_LEN,
			    NULL, KNET_MAX_PORT_LEN) || (errno != EINVAL)) {
		printf("knet_addrtostr accepted invalid addr_str or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	addrv4 = (struct sockaddr_in *)&addr;
	addrv4->sin_family = AF_INET;
	addrv4->sin_addr.s_addr = htonl(0xc0a80001); /* 192.168.0.1 */
	addrv4->sin_port = htons(50000);

	printf("Checking knet_addrtostr with valid data (192.168.0.1:50000)\n");

	if (knet_addrtostr(&addr, sizeof(struct sockaddr_storage),
			     addr_str, KNET_MAX_HOST_LEN,
			     port_str, KNET_MAX_PORT_LEN) < 0) {
		printf("Unable to convert 192.168.0.1:50000\n");
		exit(FAIL);
	}

	if (strcmp(addr_str, "192.168.0.1") != 0) {
		printf("Wrong address conversion: %s\n", addr_str);
		exit(EXIT_FAILURE);
	}

	if (strcmp(port_str, "50000") != 0) {
		printf("Wrong port conversion: %s\n", port_str);
		exit(EXIT_FAILURE);
	}

	printf("Checking knet_addrtostr with valid data ([fd00::1]:50000)\n");

	memset(&addr, 0, sizeof(struct sockaddr_storage));

	addrv6 = (struct sockaddr_in6 *)&addr;
	addrv6->sin6_family = AF_INET6;
	addrv6->sin6_addr.s6_addr32[0] = htonl(0xfd000000); /* fd00::1 */
	addrv6->sin6_addr.s6_addr32[3] = htonl(0x00000001);
	addrv6->sin6_port = htons(50000);

	if (knet_addrtostr(&addr, sizeof(struct sockaddr_storage),
			     addr_str, KNET_MAX_HOST_LEN,
			     port_str, KNET_MAX_PORT_LEN) < 0) {
		printf("Unable to convert [fd00::1]:50000\n");
		exit(FAIL);
	}

	if (strcmp(addr_str, "fd00::1") != 0) {
		printf("Wrong address conversion: %s\n", addr_str);
		exit(FAIL);
	}

	if (strcmp(port_str, "50000") != 0) {
		printf("Wrong port conversion: %s\n", port_str);
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{

	test();

	exit(PASS);
}
