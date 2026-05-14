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

#define TEST_NAME "api_knet_addrtostr"

static void test(void)
{
	int logfd;
	struct sockaddr_storage addr;
	struct sockaddr_in *addrv4;
	struct sockaddr_in6 *addrv6;
	char addr_str[KNET_MAX_HOST_LEN];
	char port_str[KNET_MAX_PORT_LEN];

	logfd = start_logging(stdout);

	memset(&addr, 0, sizeof(struct sockaddr_storage));

	log_test(logfd, "Checking knet_addrtostr with invalid ss");

	FAIL_ON_SUCCESS_NOCLEAN(knet_addrtostr(NULL, sizeof(struct sockaddr_storage),
					       addr_str, KNET_MAX_HOST_LEN,
					       port_str, KNET_MAX_PORT_LEN), EINVAL);

	log_test(logfd, "Checking knet_addrtostr with invalid sslen");

	FAIL_ON_SUCCESS_NOCLEAN(knet_addrtostr(&addr, 0,
					       addr_str, KNET_MAX_HOST_LEN,
					       port_str, KNET_MAX_PORT_LEN), EINVAL);

	log_test(logfd, "Checking knet_addrtostr with invalid addr_str");

	FAIL_ON_SUCCESS_NOCLEAN(knet_addrtostr(&addr, sizeof(struct sockaddr_storage),
					       NULL, KNET_MAX_HOST_LEN,
					       port_str, KNET_MAX_PORT_LEN), EINVAL);

	log_test(logfd, "Checking knet_addrtostr with invalid port_str");

	FAIL_ON_SUCCESS_NOCLEAN(knet_addrtostr(&addr, sizeof(struct sockaddr_storage),
					       addr_str, KNET_MAX_HOST_LEN,
					       NULL, KNET_MAX_PORT_LEN), EINVAL);

	addrv4 = (struct sockaddr_in *)&addr;
	addrv4->sin_family = AF_INET;
	addrv4->sin_addr.s_addr = htonl(0xc0a80001); /* 192.168.0.1 */
	addrv4->sin_port = htons(50000);

	log_test(logfd, "Checking knet_addrtostr with valid data (192.168.0.1:50000)");

	if (knet_addrtostr(&addr, sizeof(struct sockaddr_storage),
			     addr_str, KNET_MAX_HOST_LEN,
			     port_str, KNET_MAX_PORT_LEN) < 0) {
		log_test(logfd, "Unable to convert 192.168.0.1:50000");
		TEST_EXIT(FAIL);
	}

	if (strcmp(addr_str, "192.168.0.1") != 0) {
		log_test(logfd, "Wrong address conversion. Expected: 192.168.0.1. Got:");
		log_test(logfd, "%.253s", addr_str);
		TEST_EXIT(FAIL);
	}

	if (strcmp(port_str, "50000") != 0) {
		log_test(logfd, "Wrong port conversion: %s", port_str);
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Checking knet_addrtostr with valid data ([fd00::1]:50000)");

	memset(&addr, 0, sizeof(struct sockaddr_storage));

	addrv6 = (struct sockaddr_in6 *)&addr;
	addrv6->sin6_family = AF_INET6;
	addrv6->sin6_addr.s6_addr32[0] = htonl(0xfd000000); /* fd00::1 */
	addrv6->sin6_addr.s6_addr32[3] = htonl(0x00000001);
	addrv6->sin6_port = htons(50000);

	if (knet_addrtostr(&addr, sizeof(struct sockaddr_storage),
			     addr_str, KNET_MAX_HOST_LEN,
			     port_str, KNET_MAX_PORT_LEN) < 0) {
		log_test(logfd, "Unable to convert [fd00::1]:50000");
		TEST_EXIT(FAIL);
	}

	if (strcmp(addr_str, "fd00::1") != 0) {
		log_test(logfd, "Wrong address conversion. Expected: fd00::1. Got:");
		log_test(logfd, "%.253s", addr_str);
		TEST_EXIT(FAIL);
	}

	if (strcmp(port_str, "50000") != 0) {
		log_test(logfd, "Wrong port conversion: %s", port_str);
		TEST_EXIT(FAIL);
	}

	stop_logging();
}

int main(int argc, char *argv[])
{

	printf("[TEST] %s: Test knet addrtostr\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
