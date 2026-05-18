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

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	struct knet_handle_stats test_byte_array[2];
	struct knet_handle_stats ref_byte_array[2];
	struct knet_handle_stats stats;

	log_test(logfd, "Test knet_handle_get_stats incorrect knet_h");

	memset(&stats, 0, sizeof(struct knet_handle_stats));

	if ((!knet_handle_get_stats(NULL, &stats, sizeof(struct knet_handle_stats))) || (errno != EINVAL)) {
		log_test(logfd, "knet_handle_get_stats accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		exit(FAIL);
	}


	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_get_stats with NULL structure pointer");
	FAIL_ON_SUCCESS(knet_handle_get_stats(knet_h1, NULL, 0), EINVAL);

	log_test(logfd, "Test knet_handle_get_stats with small structure size");
	memset(test_byte_array, 0x55, sizeof(struct knet_handle_stats) * 2);
	memset(ref_byte_array, 0x55, sizeof(struct knet_handle_stats) * 2);
	FAIL_ON_ERR(knet_handle_get_stats(knet_h1, (struct knet_handle_stats *)test_byte_array, sizeof(size_t)));

	if (memcmp(&test_byte_array[1], ref_byte_array, sizeof(struct knet_handle_stats))) {
		log_test(logfd, "knet_handle_get_stats corrupted memory after stats structure");
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_handle_get_stats with valid input");
	FAIL_ON_ERR(knet_handle_get_stats(knet_h1, &stats, sizeof(struct knet_handle_stats)));

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
