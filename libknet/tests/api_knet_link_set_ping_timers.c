/*
 * Copyright (C) 2016-2022 Red Hat, Inc.  All rights reserved.
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
	struct sockaddr_storage src, dst;

	if (make_local_sockaddr(&src, 0) < 0) {
		printf("Unable to convert src to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (make_local_sockaddr(&dst, 1) < 0) {
		printf("Unable to convert dst to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_link_set_ping_timers incorrect knet_h\n");

	if ((!knet_link_set_ping_timers(NULL, 1, 0, 1000, 2000, 2048)) || (errno != EINVAL)) {
		printf("knet_link_set_ping_timers accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_link_set_ping_timers with unconfigured host_id\n");
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 2000, 2048), EINVAL);

	printf("Test knet_link_set_ping_timers with incorrect linkid\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, KNET_MAX_LINK, 1000, 2000, 2048), EINVAL);

	printf("Test knet_link_set_ping_timers with incorrect interval\n");
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, 0, 0, 2000, 2048), EINVAL);

	printf("Test knet_link_set_ping_timers with 0 timeout\n");
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 0, 2048), ENOSYS);

	printf("Test knet_link_set_ping_timers with incorrect interval\n");
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 2000, 0), EINVAL);

	printf("Test knet_link_set_ping_timers with unconfigured link\n");
	FAIL_ON_SUCCESS(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 2000, 2048), EINVAL);

	printf("Test knet_link_set_ping_timers with correct values\n");
	FAIL_ON_ERR(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0));
	FAIL_ON_ERR(knet_link_set_ping_timers(knet_h1, 1, 0, 1000, 2000, 2048));
	if ((knet_h1->host_index[1]->link[0].ping_interval != 1000000) ||
	    (knet_h1->host_index[1]->link[0].pong_timeout != 2000000) ||
	    (knet_h1->host_index[1]->link[0].latency_max_samples != 2048)) {
		printf("knet_link_set_ping_timers failed to set values\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
