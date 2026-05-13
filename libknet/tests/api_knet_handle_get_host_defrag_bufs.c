/*
 * Copyright (C) 2021-2026 Red Hat, Inc.  All rights reserved.
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

#define TEST_NAME "api_knet_handle_get_host_defrag_bufs"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	uint16_t min_defrag_bufs, max_defrag_bufs;
	uint8_t shrink_threshold;
	defrag_bufs_reclaim_policy_t reclaim_policy;

	log_test(logfd, "Test knet_handle_get_host_defrag_bufs incorrect knet_h");

	if ((!knet_handle_get_host_defrag_bufs(NULL, &min_defrag_bufs, &max_defrag_bufs, &shrink_threshold, &reclaim_policy)) || (errno != EINVAL)) {
		log_test(logfd, "knet_handle_get_host_defrag_bufs accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_get_host_defrag_bufs with invalid min_defrag_bufs");
	FAIL_ON_SUCCESS(knet_handle_get_host_defrag_bufs(knet_h1, NULL, &max_defrag_bufs, &shrink_threshold, &reclaim_policy), EINVAL);

	log_test(logfd, "Test knet_handle_get_host_defrag_bufs with invalid max_defrag_bufs");
	FAIL_ON_SUCCESS(knet_handle_get_host_defrag_bufs(knet_h1, &min_defrag_bufs, NULL, &shrink_threshold, &reclaim_policy), EINVAL);

	log_test(logfd, "Test knet_handle_get_host_defrag_bufs with invalid shrink_threshold");
	FAIL_ON_SUCCESS(knet_handle_get_host_defrag_bufs(knet_h1, &min_defrag_bufs, &max_defrag_bufs, NULL, &reclaim_policy), EINVAL);

	log_test(logfd, "Test knet_handle_get_host_defrag_bufs with invalid reclaim_policy");
	FAIL_ON_SUCCESS(knet_handle_get_host_defrag_bufs(knet_h1, &min_defrag_bufs, &max_defrag_bufs, &shrink_threshold, NULL), EINVAL);

	log_test(logfd, "Test knet_handle_get_host_defrag_bufs with valid data");
	FAIL_ON_ERR(knet_handle_get_host_defrag_bufs(knet_h1, &min_defrag_bufs, &max_defrag_bufs, &shrink_threshold, &reclaim_policy));

	log_test(logfd, "Test knet_handle_get_host_defrag_bufs default data");
	if ((min_defrag_bufs != KNET_MIN_DEFRAG_BUFS_DEFAULT) ||
	    (max_defrag_bufs != KNET_MAX_DEFRAG_BUFS_DEFAULT) ||
	    (shrink_threshold != KNET_SHRINK_THRESHOLD_DEFAULT) ||
	    (reclaim_policy != RECLAIM_POLICY_ABSOLUTE)) {
		log_test(logfd, "knet_handle_get_host_defrag_bufs returned incorrect default data");
		TEST_EXIT_CLEAN(FAIL);
	}

	knet_h1->defrag_bufs_reclaim_policy = RECLAIM_POLICY_AVERAGE;

	log_test(logfd, "Test knet_handle_get_host_defrag_bufs with reclaim_policy override");
	FAIL_ON_ERR(knet_handle_get_host_defrag_bufs(knet_h1, &min_defrag_bufs, &max_defrag_bufs, &shrink_threshold, &reclaim_policy));

	if ((min_defrag_bufs != KNET_MIN_DEFRAG_BUFS_DEFAULT) ||
	    (max_defrag_bufs != KNET_MAX_DEFRAG_BUFS_DEFAULT) ||
	    (shrink_threshold != KNET_SHRINK_THRESHOLD_DEFAULT) ||
	    (reclaim_policy != RECLAIM_POLICY_AVERAGE)) {
		log_test(logfd, "knet_handle_get_host_defrag_bufs returned incorrect default data");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle get host defrag bufs\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
