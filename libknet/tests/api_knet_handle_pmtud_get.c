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

#define TEST_NAME "api_knet_handle_pmtud_get"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	unsigned int data_mtu;

	log_test(logfd, "Test knet_handle_pmtud_get incorrect knet_h");

	if ((!knet_handle_pmtud_get(NULL, &data_mtu)) || (errno != EINVAL)) {
		log_test(logfd, "knet_handle_pmtud_get accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);


	log_test(logfd, "Test knet_handle_pmtud_get with no data_mtu");
	FAIL_ON_SUCCESS(knet_handle_pmtud_get(knet_h1, NULL), EINVAL);

	FAIL_ON_ERR(knet_handle_pmtud_get(knet_h1, &data_mtu));

	if (knet_h1->data_mtu != data_mtu) {
		log_test(logfd, "knet_handle_pmtud_get failed to set the value");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle pmtud get\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
