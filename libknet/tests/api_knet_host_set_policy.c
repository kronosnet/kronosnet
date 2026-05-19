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
#include "test-common.h"

#define TEST_NAME "api_knet_host_set_policy"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2] = {0};

	log_test(logfd, "Test knet_host_set_policy incorrect knet_h");

	FAIL_ON_SUCCESS(knet_host_set_policy(NULL, 1, KNET_LINK_POLICY_PASSIVE), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);


	log_test(logfd, "Test knet_host_set_policy incorrect host_id");
	FAIL_ON_SUCCESS(knet_host_set_policy(knet_h1, 1, KNET_LINK_POLICY_PASSIVE), EINVAL);

	log_test(logfd, "Test knet_host_set_policy incorrect policy");
	FAIL_ON_SUCCESS(knet_host_set_policy(knet_h1, 1, KNET_LINK_POLICY_RR + 1), EINVAL);

	log_test(logfd, "Test knet_host_set_policy correct policy");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(knet_host_set_policy(knet_h1, 1, KNET_LINK_POLICY_RR));
	if (knet_h1->host_index[1]->link_handler_policy != KNET_LINK_POLICY_RR) {
		log_test(logfd, "knet_host_set_policy failed to set RR policy for host 1: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet host set policy\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
