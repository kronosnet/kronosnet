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
	unsigned int enabled;
	struct sockaddr_storage lo;

	printf("Test knet_link_get_enable incorrect knet_h\n");

	if ((!knet_link_get_enable(NULL, 1, 0, &enabled)) || (errno != EINVAL)) {
		printf("knet_link_get_enable accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_link_get_enable with unconfigured host_id\n");
	FAIL_ON_SUCCESS(knet_link_get_enable(knet_h1, 1, 0, &enabled), EINVAL);

	printf("Test knet_link_get_enable with incorrect linkid\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_get_enable(knet_h1, 1, KNET_MAX_LINK, &enabled), EINVAL);

	printf("Test knet_link_get_enable with unconfigured link\n");
	FAIL_ON_SUCCESS(knet_link_get_enable(knet_h1, 1, 0, &enabled), EINVAL);

	printf("Test knet_link_get_enable without enabled\n");
	FAIL_ON_SUCCESS(knet_link_get_enable(knet_h1, 1, 0, NULL), EINVAL);

	printf("Test knet_link_get_enable with disabled link\n");
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo));
	FAIL_ON_ERR(knet_link_get_enable(knet_h1, 1, 0, &enabled));
	if (enabled) {
		printf("knet_link_get_enable returned incorrect value");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_link_get_enable with enabled link\n");
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_link_get_enable(knet_h1, 1, 0, &enabled));
	if (!enabled) {
		printf("knet_link_get_enable returned incorrect value");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
