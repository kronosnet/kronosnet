/*
 * Copyright (C) 2021-2024 Red Hat, Inc.  All rights reserved.
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

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	uint16_t min_defrag_bufs, max_defrag_bufs;
	uint8_t shrink_threshold;
	defrag_bufs_reclaim_policy_t reclaim_policy;

	printf("Test knet_handle_get_host_defrag_bufs incorrect knet_h\n");

	if ((!knet_handle_get_host_defrag_bufs(NULL, &min_defrag_bufs, &max_defrag_bufs, &shrink_threshold, &reclaim_policy)) || (errno != EINVAL)) {
		printf("knet_handle_get_host_defrag_bufs accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_get_host_defrag_bufs with invalid min_defrag_bufs\n");
	FAIL_ON_SUCCESS(knet_handle_get_host_defrag_bufs(knet_h1, NULL, &max_defrag_bufs, &shrink_threshold, &reclaim_policy), EINVAL);

	printf("Test knet_handle_get_host_defrag_bufs with invalid max_defrag_bufs\n");
	FAIL_ON_SUCCESS(knet_handle_get_host_defrag_bufs(knet_h1, &min_defrag_bufs, NULL, &shrink_threshold, &reclaim_policy), EINVAL);

	printf("Test knet_handle_get_host_defrag_bufs with invalid shrink_threshold\n");
	FAIL_ON_SUCCESS(knet_handle_get_host_defrag_bufs(knet_h1, &min_defrag_bufs, &max_defrag_bufs, NULL, &reclaim_policy), EINVAL);

	printf("Test knet_handle_get_host_defrag_bufs with invalid reclaim_policy\n");
	FAIL_ON_SUCCESS(knet_handle_get_host_defrag_bufs(knet_h1, &min_defrag_bufs, &max_defrag_bufs, &shrink_threshold, NULL), EINVAL);

	printf("Test knet_handle_get_host_defrag_bufs with valid data\n");
	FAIL_ON_ERR(knet_handle_get_host_defrag_bufs(knet_h1, &min_defrag_bufs, &max_defrag_bufs, &shrink_threshold, &reclaim_policy));

	printf("Test knet_handle_get_host_defrag_bufs default data\n");
	if ((min_defrag_bufs != KNET_MIN_DEFRAG_BUFS_DEFAULT) ||
	    (max_defrag_bufs != KNET_MAX_DEFRAG_BUFS_DEFAULT) ||
	    (shrink_threshold != KNET_SHRINK_THRESHOLD_DEFAULT) ||
	    (reclaim_policy != RECLAIM_POLICY_ABSOLUTE)) {
		printf("knet_handle_get_host_defrag_bufs returned incorrect default data\n");
		CLEAN_EXIT(FAIL);
	}

	knet_h1->defrag_bufs_reclaim_policy = RECLAIM_POLICY_AVERAGE;

	printf("Test knet_handle_get_host_defrag_bufs with reclaim_policy override\n");
	FAIL_ON_ERR(knet_handle_get_host_defrag_bufs(knet_h1, &min_defrag_bufs, &max_defrag_bufs, &shrink_threshold, &reclaim_policy));

	if ((min_defrag_bufs != KNET_MIN_DEFRAG_BUFS_DEFAULT) ||
	    (max_defrag_bufs != KNET_MAX_DEFRAG_BUFS_DEFAULT) ||
	    (shrink_threshold != KNET_SHRINK_THRESHOLD_DEFAULT) ||
	    (reclaim_policy != RECLAIM_POLICY_AVERAGE)) {
		printf("knet_handle_get_host_defrag_bufs returned incorrect default data\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
