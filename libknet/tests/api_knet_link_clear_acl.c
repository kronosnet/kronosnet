/*
 * Copyright (C) 2019-2026 Red Hat, Inc.  All rights reserved.
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
#include <inttypes.h>

#include "libknet.h"

#include "internals.h"
#include "netutils.h"
#include "test-common.h"

#define TEST_NAME "api_knet_link_clear_acl"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2] = {0};
	struct knet_host *host;
	struct knet_link *link;
	struct sockaddr_storage lo;

	log_test(logfd, "Test knet_link_clear_acl incorrect knet_h");

	FAIL_ON_SUCCESS(knet_link_clear_acl(NULL, 1, 0), EINVAL);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_clear_acl with unconfigured host");
	FAIL_ON_SUCCESS(knet_link_clear_acl(knet_h1, 1, 0), EINVAL);

	log_test(logfd, "Test knet_link_clear_acl with unconfigured link");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_clear_acl(knet_h1, 1, 0), EINVAL);

	log_test(logfd, "Test knet_link_clear_acl with invalid link");
	FAIL_ON_SUCCESS(knet_link_clear_acl(knet_h1, 1, KNET_MAX_LINK), EINVAL);

	log_test(logfd, "Test knet_link_clear_acl with point to point link");
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_SUCCESS(knet_link_clear_acl(knet_h1, 1, 0), EINVAL);
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));

	log_test(logfd, "Test knet_link_clear_acl with dynamic link");
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 1, &lo, logfd));

	host = knet_h1->host_index[1];
	link = &host->link[0];

	if (link->access_list_match_entry_head) {
		log_test(logfd, "match list NOT empty!");
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(knet_link_add_acl(knet_h1, 1, 0, &lo, &lo, CHECK_TYPE_ADDRESS, CHECK_ACCEPT));
	if (!link->access_list_match_entry_head) {
		log_test(logfd, "match list empty!");
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(knet_link_clear_acl(knet_h1, 1, 0));
	if (link->access_list_match_entry_head) {
		log_test(logfd, "match list NOT empty!");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet link clear acl\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
