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

#define TEST_NAME "api_knet_link_set_ping_timers"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2] = {0};
	struct sockaddr_storage src, dst;

	if (make_local_sockaddr(&src, 0, logfd) < 0) {
		log_test(logfd, "Unable to convert src to sockaddr: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (make_local_sockaddr(&dst, 1, logfd) < 0) {
		log_test(logfd, "Unable to convert dst to sockaddr: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_link_set_ping_timers incorrect knet_h");

	FAIL_ON_SUCCESS(knet_link_set_ping_timers(NULL, 1, 0, 1000, 2000, 2048), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_set_ping_timers with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 2000, 2048), EINVAL);

	log_test(logfd, "Test knet_link_set_ping_timers with incorrect linkid");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, KNET_MAX_LINK, 1000, 2000, 2048), EINVAL);

	log_test(logfd, "Test knet_link_set_ping_timers with incorrect interval");
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, 0, 0, 2000, 2048), EINVAL);

	log_test(logfd, "Test knet_link_set_ping_timers with 0 timeout");
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 0, 2048), ENOSYS);

	log_test(logfd, "Test knet_link_set_ping_timers with incorrect interval");
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 2000, 0), EINVAL);

	log_test(logfd, "Test knet_link_set_ping_timers with unconfigured link");
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 2000, 2048), EINVAL);

	log_test(logfd, "Configure link");
	FAIL_ON_ERR(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0));

	log_test(logfd, "Test knet_link_set_ping_timers with too small timeout");
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, (KNET_THREADS_TIMERES / 2000), 2048), EINVAL);

	log_test(logfd, "Test knet_link_set_ping_timers with correct values");
	FAIL_ON_ERR(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 2000, 2048));
	if ((knet_h1->host_index[1]->link[0].ping_interval != 1000000) ||
	    (knet_h1->host_index[1]->link[0].pong_timeout != 2000000) ||
	    (knet_h1->host_index[1]->link[0].latency_max_samples != 2048)) {
		log_test(logfd, "knet_link_set_ping_timers failed to set values");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet link set ping timers\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
