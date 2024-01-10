/*
 * Copyright (C) 2016-2024 Red Hat, Inc.  All rights reserved.
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
	int logfds[2];
	struct knet_handle_stats test_byte_array[2];
	struct knet_handle_stats ref_byte_array[2];
	struct knet_handle_stats stats;
	int res;

	printf("Test knet_handle_get_stats incorrect knet_h\n");

	memset(&stats, 0, sizeof(struct knet_handle_stats));

	if ((!knet_handle_get_stats(NULL, &stats, sizeof(struct knet_handle_stats))) || (errno != EINVAL)) {
		printf("knet_handle_get_stats accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_get_stats with NULL structure pointer\n");
	FAIL_ON_SUCCESS(knet_handle_get_stats(knet_h1, NULL, 0), EINVAL);

	printf("Test knet_handle_get_stats with small structure size\n");
	memset(test_byte_array, 0x55, sizeof(struct knet_handle_stats) * 2);
	memset(ref_byte_array, 0x55, sizeof(struct knet_handle_stats) * 2);
	FAIL_ON_ERR(knet_handle_get_stats(knet_h1, (struct knet_handle_stats *)test_byte_array, sizeof(size_t)));

	if (memcmp(&test_byte_array[1], ref_byte_array, sizeof(struct knet_handle_stats))) {
		printf("knet_handle_get_stats corrupted memory after stats structure\n");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_get_stats with valid input\n");
	FAIL_ON_ERR(knet_handle_get_stats(knet_h1, &stats, sizeof(struct knet_handle_stats)));

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
