/*
 * Copyright (C) 2016-2026 Red Hat, Inc.  All rights reserved.
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

#define TEST_NAME "api_knet_link_get_ping_timers"

static void test(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	time_t interval = 0, timeout = 0;
	unsigned int precision = 0;
	struct sockaddr_storage lo;

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_link_get_ping_timers incorrect knet_h");

	FAIL_ON_SUCCESS(knet_link_get_ping_timers(NULL, 1, 0, &interval, &timeout, &precision), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_get_ping_timers with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, 0, &interval, &timeout, &precision), EINVAL);

	log_test(logfd, "Test knet_link_get_ping_timers with incorrect linkid");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, KNET_MAX_LINK, &interval, &timeout, &precision), EINVAL);

	log_test(logfd, "Test knet_link_get_ping_timers with incorrect interval");
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, 0, NULL, &timeout, &precision), EINVAL);

	log_test(logfd, "Test knet_link_get_ping_timers with incorrect timeout");
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, 0, &interval, NULL, &precision), EINVAL);

	log_test(logfd, "Test knet_link_get_ping_timers with incorrect interval");
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, 0, &interval, &timeout, NULL), EINVAL);

	log_test(logfd, "Test knet_link_get_ping_timers with unconfigured link");
	FAIL_ON_SUCCESS(knet_link_get_ping_timers(knet_h1, 1, 0, &interval, &timeout, &precision), EINVAL);

	log_test(logfd, "Test knet_link_get_ping_timers with correct values");
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_get_ping_timers(knet_h1, 1, 0, &interval, &timeout, &precision));

	log_test(logfd, "DEFAULT: int: %ld timeout: %ld prec: %u", (long int)interval, (long int)timeout, precision);
	if ((interval != KNET_LINK_DEFAULT_PING_INTERVAL) ||
	    (timeout != KNET_LINK_DEFAULT_PING_TIMEOUT) ||
	    (precision != KNET_LINK_DEFAULT_PING_PRECISION)) {
		log_test(logfd, "knet_link_get_ping_timers failed to set values");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet link get ping timers\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
