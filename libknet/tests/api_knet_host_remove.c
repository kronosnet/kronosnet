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

#include "netutils.h"
#include "test-common.h"

#define TEST_NAME "api_knet_host_remove"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	knet_node_id_t host_ids[KNET_MAX_HOST];
	size_t host_ids_entries;
	struct sockaddr_storage lo;

	log_test(logfd, "Test knet_host_add incorrect knet_h");

	if ((!knet_host_remove(NULL, 1)) || (errno != EINVAL)) {
		log_test(logfd, "knet_host_remove accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}


	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);


	log_test(logfd, "Test knet_host_remove with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_host_remove(knet_h1, 1), EINVAL);
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));

	log_test(logfd, "Test knet_host_remove with configured host_id and links");
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 1, &lo, logfd));
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));

	if ((!knet_host_remove(knet_h1, 1)) || (errno != EBUSY)) {
		log_test(logfd, "knet_host_remove accepted invalid request to remove host with link enabled or returned incorrect error: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 0));
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));

	log_test(logfd, "Test knet_host_remove with configured host_id (no links)");
	FAIL_ON_ERR(knet_host_remove(knet_h1, 1));

	FAIL_ON_ERR(knet_host_get_host_list(knet_h1, host_ids, &host_ids_entries));

	if (host_ids_entries) {
		log_test(logfd, "Too many hosts?");
		TEST_EXIT_CLEAN(FAIL);
	}

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet host remove\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
