/*
 * Copyright (C) 2020-2026 Red Hat, Inc.  All rights reserved.
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
#include "crypto_model.h"
#include "test-common.h"

#define TEST_NAME "api_knet_handle_crypto_rx_clear_traffic"

static void test()
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_handle_crypto_rx_clear_traffic incorrect knet_h");

	FAIL_ON_SUCCESS(knet_handle_crypto_rx_clear_traffic(NULL, 1), EINVAL);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_crypto_rx_clear_traffic with invalid value");
	FAIL_ON_SUCCESS(knet_handle_crypto_rx_clear_traffic(knet_h1, 2), EINVAL);

	log_test(logfd, "Test knet_handle_crypto_rx_clear_traffic with valid value KNET_CRYPTO_RX_ALLOW_CLEAR_TRAFFIC");
	FAIL_ON_ERR(knet_handle_crypto_rx_clear_traffic(knet_h1, KNET_CRYPTO_RX_ALLOW_CLEAR_TRAFFIC));
	if (knet_h1->crypto_only != KNET_CRYPTO_RX_ALLOW_CLEAR_TRAFFIC) {
		log_test(logfd, "knet_handle_crypto_rx_clear_traffic failed to set correct value");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_handle_crypto_rx_clear_traffic with valid value KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC");
	FAIL_ON_ERR(knet_handle_crypto_rx_clear_traffic(knet_h1, KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC));
	if (knet_h1->crypto_only != KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC) {
		log_test(logfd, "knet_handle_crypto_rx_clear_traffic failed to set correct value");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle crypto rx clear traffic\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
