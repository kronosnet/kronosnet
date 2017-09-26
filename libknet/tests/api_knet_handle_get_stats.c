/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
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
	knet_handle_t knet_h;
	int logfds[2];
	struct knet_handle_stats test_byte_array[2];
	struct knet_handle_stats ref_byte_array[2];
	struct knet_handle_stats stats;

	printf("Test knet_handle_get_stats incorrect knet_h\n");

	memset(&stats, 0, sizeof(struct knet_handle_stats));

	if ((!knet_handle_get_stats(NULL, &stats, sizeof(struct knet_handle_stats))) || (errno != EINVAL)) {
		printf("knet_handle_get_stats accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG);

	if (!knet_h) {
		printf("knet_handle_new failed: %s\n", strerror(errno));
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Test knet_handle_get_stats with NULL structure pointer\n");

	if ((!knet_handle_get_stats(knet_h, NULL, 0) || (errno != EINVAL))) {
		printf("knet_handle_get_stats accepted invalid stats address or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_stats with small structure size\n");

	memset(test_byte_array, 0x55, sizeof(struct knet_handle_stats) * 2);
	memset(ref_byte_array, 0x55, sizeof(struct knet_handle_stats) * 2);
	if (knet_handle_get_stats(knet_h, (struct knet_handle_stats *)test_byte_array, sizeof(size_t)) < 0) {
		printf("knet_handle_get_stats failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (memcmp(&test_byte_array[1], ref_byte_array, sizeof(struct knet_handle_stats))) {
		printf("knet_handle_get_stats corrupted memory after stats structure\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_stats with valid input\n");

	if (knet_handle_get_stats(knet_h, &stats, sizeof(struct knet_handle_stats)) < 0) {
		printf("knet_handle_get_stats failed: %s\n", strerror(errno));
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
	need_root();

	test();

	return PASS;
}
