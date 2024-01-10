/*
 * Copyright (C) 2020-2024 Red Hat, Inc.  All rights reserved.
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

static void test()
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];

	printf("Test knet_handle_crypto_rx_clear_traffic incorrect knet_h\n");

	if ((!knet_handle_crypto_rx_clear_traffic(NULL, 1)) || (errno != EINVAL)) {
		printf("knet_handle_crypto_rx_clear_traffic accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_crypto_rx_clear_traffic with invalid value\n");
	FAIL_ON_SUCCESS(knet_handle_crypto_rx_clear_traffic(knet_h1, 2), EINVAL);

	printf("Test knet_handle_crypto_rx_clear_traffic with valid value KNET_CRYPTO_RX_ALLOW_CLEAR_TRAFFIC\n");
	FAIL_ON_ERR(knet_handle_crypto_rx_clear_traffic(knet_h1, KNET_CRYPTO_RX_ALLOW_CLEAR_TRAFFIC));
	if (knet_h1->crypto_only != KNET_CRYPTO_RX_ALLOW_CLEAR_TRAFFIC) {
		printf("knet_handle_crypto_rx_clear_traffic failed to set correct value\n");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_crypto_rx_clear_traffic with valid value KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC\n");
	FAIL_ON_ERR(knet_handle_crypto_rx_clear_traffic(knet_h1, KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC));
	if (knet_h1->crypto_only != KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC) {
		printf("knet_handle_crypto_rx_clear_traffic failed to set correct value\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
