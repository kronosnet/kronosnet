/*
 * Copyright (C) 2020-2021 Red Hat, Inc.  All rights reserved.
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
	knet_handle_t knet_h;
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

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_handle_get_host_defrag_bufs with invalid min_defrag_bufs\n");

	if ((!knet_handle_get_host_defrag_bufs(knet_h, NULL, &max_defrag_bufs, &shrink_threshold, &reclaim_policy)) || (errno != EINVAL)) {
		printf("knet_handle_get_host_defrag_bufs accepted invalid min_defrag_bufs or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_host_defrag_bufs with invalid max_defrag_bufs\n");

	if ((!knet_handle_get_host_defrag_bufs(knet_h, &min_defrag_bufs, NULL, &shrink_threshold, &reclaim_policy)) || (errno != EINVAL)) {
		printf("knet_handle_get_host_defrag_bufs accepted invalid max_defrag_bufs or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_host_defrag_bufs with invalid shrink_threshold\n");

	if ((!knet_handle_get_host_defrag_bufs(knet_h, &min_defrag_bufs, &max_defrag_bufs, NULL, &reclaim_policy)) || (errno != EINVAL)) {
		printf("knet_handle_get_host_defrag_bufs accepted invalid shrink_threshold or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_host_defrag_bufs with invalid reclaim_policy\n");

	if ((!knet_handle_get_host_defrag_bufs(knet_h, &min_defrag_bufs, &max_defrag_bufs, &shrink_threshold, NULL)) || (errno != EINVAL)) {
		printf("knet_handle_get_host_defrag_bufs accepted invalid reclaim_policy or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_host_defrag_bufs with valid data\n");

	if (knet_handle_get_host_defrag_bufs(knet_h, &min_defrag_bufs, &max_defrag_bufs, &shrink_threshold, &reclaim_policy) < 0) {
		printf("knet_handle_get_host_defrag_bufs did not accepted valid data. error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_host_defrag_bufs default data\n");

	if ((min_defrag_bufs != KNET_MIN_DEFRAG_BUFS_DEFAULT) ||
	    (max_defrag_bufs != KNET_MAX_DEFRAG_BUFS_DEFAULT) ||
	    (shrink_threshold != KNET_SHRINK_THRESHOLD_DEFAULT) ||
	    (reclaim_policy != RECLAIM_POLICY_ABSOLUTE)) {
		printf("knet_handle_get_host_defrag_bufs returned incorrect default data\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	knet_h->defrag_bufs_reclaim_policy = RECLAIM_POLICY_AVERAGE;

	printf("Test knet_handle_get_host_defrag_bufs with reclaim_policy override\n");

	if (knet_handle_get_host_defrag_bufs(knet_h, &min_defrag_bufs, &max_defrag_bufs, &shrink_threshold, &reclaim_policy) < 0) {
		printf("knet_handle_get_host_defrag_bufs did not accepted valid data. error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((min_defrag_bufs != KNET_MIN_DEFRAG_BUFS_DEFAULT) ||
	    (max_defrag_bufs != KNET_MAX_DEFRAG_BUFS_DEFAULT) ||
	    (shrink_threshold != KNET_SHRINK_THRESHOLD_DEFAULT) ||
	    (reclaim_policy != RECLAIM_POLICY_AVERAGE)) {
		printf("knet_handle_get_host_defrag_bufs returned incorrect default data\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
