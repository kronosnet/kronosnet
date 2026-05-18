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

static void test_udp(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	struct sockaddr_storage src, dst;

	if (make_local_sockaddr(&src, 0, logfd) < 0) {
		log_test(logfd, "Unable to convert src to sockaddr: %s", strerror(errno));
		exit(FAIL);
	}

	if (make_local_sockaddr(&dst, 1, logfd) < 0) {
		log_test(logfd, "Unable to convert dst to sockaddr: %s", strerror(errno));
		exit(FAIL);
	}

	log_test(logfd, "Test knet_link_set_enable incorrect knet_h");

	if ((!knet_link_set_enable(NULL, 1, 0, 1)) || (errno != EINVAL)) {
		log_test(logfd, "knet_link_set_enable accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		exit(FAIL);
	}

	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_set_enable with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, 0, 1), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with incorrect linkid");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, KNET_MAX_LINK, 1), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with unconfigured link");
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, 0, 1), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with incorrect values");
	FAIL_ON_ERR(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0));
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, 0, 2), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with correct values (1)");
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	if (knet_h1->host_index[1]->link[0].status.enabled != 1) {
		log_test(logfd, "knet_link_set_enable failed to set correct values");
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_link_set_enable with correct values (0)");
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 0));
	if (knet_h1->host_index[1]->link[0].status.enabled != 0) {
		log_test(logfd, "knet_link_set_enable failed to set correct values");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}


int main(int argc, char *argv[])
{
	printf("Testing with UDP\n");

	test_udp();

	return PASS;
}
