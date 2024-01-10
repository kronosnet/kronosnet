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
#include "test-common.h"

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
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];

	printf("Test knet_handle_enable_filter incorrect knet_h\n");

	if ((!knet_handle_enable_filter(NULL, NULL, dhost_filter)) || (errno != EINVAL)) {
		printf("knet_handle_enable_filter accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_enable_filter with no private_data\n");
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, NULL, dhost_filter));

	if (knet_h1->dst_host_filter_fn_private_data != NULL) {
		printf("knet_handle_enable_filter failed to unset private_data");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_enable_filter with private_data\n");
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, &private_data, NULL));

	if (knet_h1->dst_host_filter_fn_private_data != &private_data) {
		printf("knet_handle_enable_filter failed to set private_data");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_enable_filter with no dhost_filter fn\n");
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, NULL, NULL));

	if (knet_h1->dst_host_filter_fn != NULL) {
		printf("knet_handle_enable_filter failed to unset dhost_filter fn");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_enable_filter with dhost_filter fn\n");
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, NULL, dhost_filter));

	if (knet_h1->dst_host_filter_fn != &dhost_filter) {
		printf("knet_handle_enable_filter failed to set dhost_filter fn");
		CLEAN_EXIT(FAIL);
	}

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
