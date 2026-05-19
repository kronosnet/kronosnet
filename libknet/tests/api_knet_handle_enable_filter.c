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

#define TEST_NAME "api_knet_handle_enable_filter"

static int private_data;

static int dhost_filter(void *pvt_data,
			const unsigned char *outdata,
			ssize_t outdata_len,
			uint8_t tx_rx,
			knet_node_id_t this_host_id,
			knet_node_id_t src_host_id,
			int8_t *dst_channel,
			knet_node_id_t *dst_host_ids,
			size_t *dst_host_ids_entries)
{
	return 0;
}

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2] = {0};

	log_test(logfd, "Test knet_handle_enable_filter incorrect knet_h");

	FAIL_ON_SUCCESS(knet_handle_enable_filter(NULL, NULL, dhost_filter), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_enable_filter with no private_data");
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, NULL, dhost_filter));

	if (knet_h1->dst_host_filter_fn_private_data != NULL) {
		log_test(logfd, "knet_handle_enable_filter failed to unset private_data");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_handle_enable_filter with private_data");
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, &private_data, NULL));

	if (knet_h1->dst_host_filter_fn_private_data != &private_data) {
		log_test(logfd, "knet_handle_enable_filter failed to set private_data");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_handle_enable_filter with no dhost_filter fn");
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, NULL, NULL));

	if (knet_h1->dst_host_filter_fn != NULL) {
		log_test(logfd, "knet_handle_enable_filter failed to unset dhost_filter fn");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_handle_enable_filter with dhost_filter fn");
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, NULL, dhost_filter));

	if (knet_h1->dst_host_filter_fn != &dhost_filter) {
		log_test(logfd, "knet_handle_enable_filter failed to set dhost_filter fn");
		TEST_EXIT_CLEAN(FAIL);
	}

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle enable filter\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
