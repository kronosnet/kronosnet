/*
 * Copyright (C) 2016-2024 Red Hat, Inc.  All rights reserved.
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
	time_t interval = 0, timeout = 0;
	unsigned int precision = 0;
	struct sockaddr_storage lo;

	printf("Test knet_link_get_ping_timers incorrect knet_h\n");

	if ((!knet_link_get_ping_timers(NULL, 1, 0, &interval, &timeout, &precision)) || (errno != EINVAL)) {
		printf("knet_link_get_ping_timers accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_link_get_ping_timers with unconfigured host_id\n");
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, 0, &interval, &timeout, &precision), EINVAL);

	printf("Test knet_link_get_ping_timers with incorrect linkid\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, KNET_MAX_LINK, &interval, &timeout, &precision), EINVAL);

	printf("Test knet_link_get_ping_timers with incorrect interval\n");
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, 0, NULL, &timeout, &precision), EINVAL);

	printf("Test knet_link_get_ping_timers with incorrect timeout\n");
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, 0, &interval, NULL, &precision), EINVAL);

	printf("Test knet_link_get_ping_timers with incorrect interval\n");
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, 0, &interval, &timeout, NULL), EINVAL);

	printf("Test knet_link_get_ping_timers with unconfigured link\n");
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, 0, &interval, &timeout, &precision), EINVAL);

	printf("Test knet_link_get_ping_timers with correct values\n");
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo));
	FAIL_ON_ERR(knet_link_get_ping_timers(knet_h1, 1, 0, &interval, &timeout, &precision));

	printf("DEFAULT: int: %ld timeout: %ld prec: %u\n", (long int)interval, (long int)timeout, precision);
	if ((interval != KNET_LINK_DEFAULT_PING_INTERVAL) ||
	    (timeout != KNET_LINK_DEFAULT_PING_TIMEOUT) ||
	    (precision != KNET_LINK_DEFAULT_PING_PRECISION)) {
		printf("knet_link_get_ping_timers failed to set values\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
