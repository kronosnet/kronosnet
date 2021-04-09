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
#include "crypto_model.h"
#include "test-common.h"

static void test()
{
	knet_handle_t knet_h;
	int logfds[2];

	printf("Test knet_handle_crypto_rx_clear_traffic incorrect knet_h\n");

	if ((!knet_handle_crypto_rx_clear_traffic(NULL, 1)) || (errno != EINVAL)) {
		printf("knet_handle_crypto_rx_clear_traffic accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_crypto_rx_clear_traffic with invalid value\n");

	if ((!knet_handle_crypto_rx_clear_traffic(knet_h, 2)) || (errno != EINVAL)) {
		printf("knet_handle_crypto_rx_clear_traffic accepted invalid value (%u) or returned incorrect error: %s\n", 2, strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_crypto_rx_clear_traffic with valid value KNET_CRYPTO_RX_ALLOW_CLEAR_TRAFFIC\n");

	if ((knet_handle_crypto_rx_clear_traffic(knet_h, KNET_CRYPTO_RX_ALLOW_CLEAR_TRAFFIC)) < 0) {
		printf("knet_handle_crypto_rx_clear_traffic did not accept valid value\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->crypto_only != KNET_CRYPTO_RX_ALLOW_CLEAR_TRAFFIC) {
		printf("knet_handle_crypto_rx_clear_traffic failed to set correct value\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_crypto_rx_clear_traffic with valid value KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC\n");

	if ((knet_handle_crypto_rx_clear_traffic(knet_h, KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC)) < 0) {
		printf("knet_handle_crypto_rx_clear_traffic did not accept valid value\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->crypto_only != KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC) {
		printf("knet_handle_crypto_rx_clear_traffic failed to set correct value\n");
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
