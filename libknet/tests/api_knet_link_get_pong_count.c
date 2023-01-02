/*
 * Copyright (C) 2016-2023 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libknet.h"

#include "internals.h"
#include "link.h"
#include "netutils.h"
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	uint8_t pong_count = 0;
	struct sockaddr_storage lo;

	printf("Test knet_link_get_pong_count incorrect knet_h\n");

	if ((!knet_link_get_pong_count(NULL, 1, 0, &pong_count)) || (errno != EINVAL)) {
		printf("knet_link_get_pong_count accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_link_get_pong_count with unconfigured host_id\n");
	FAIL_ON_SUCCESS(knet_link_get_pong_count(knet_h1, 1, 0, &pong_count), EINVAL);

	printf("Test knet_link_get_pong_count with incorrect linkid\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_get_pong_count(knet_h1, 1, KNET_MAX_LINK, &pong_count), EINVAL);

	printf("Test knet_link_get_pong_count with incorrect pong count\n");
	FAIL_ON_SUCCESS(knet_link_get_pong_count(knet_h1, 1, 0, NULL), EINVAL);

	printf("Test knet_link_get_pong_count with unconfigured link\n");
	FAIL_ON_SUCCESS(knet_link_get_pong_count(knet_h1, 1, 0, &pong_count), EINVAL);

	printf("Test knet_link_get_pong_count with correct values\n");
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo));
	FAIL_ON_ERR(knet_link_set_pong_count(knet_h1, 1, 0, 3));
	FAIL_ON_ERR(knet_link_get_pong_count(knet_h1, 1, 0, &pong_count));
	if (pong_count != 3) {
		printf("knet_link_get_pong_count failed to get correct values\n");
		CLEAN_EXIT(FAIL);
	}

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
