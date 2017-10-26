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
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	const char *crypto_list[16];
	size_t crypto_list_entries;
	size_t crypto_list_entries1;
	size_t i;

	memset(crypto_list, 0, sizeof(crypto_list));

	printf("Test knet_handle_get_crypto_list with incorrect knet_h\n");

	if (!knet_handle_get_crypto_list(NULL, crypto_list, &crypto_list_entries) || (errno != EINVAL)) {
		printf("knet_handle_get_crypto_list accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
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

	printf("Test knet_handle_get_crypto_list with no entries_list\n");

	if ((!knet_handle_get_crypto_list(knet_h, crypto_list, NULL)) || (errno != EINVAL)) {
		printf("knet_handle_get_crypto_list accepted invalid list_entries or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_crypto_list with no crypto_list (get number of entries)\n");

	if (knet_handle_get_crypto_list(knet_h, NULL, &crypto_list_entries) < 0) {
		printf("knet_handle_get_crypto_list returned error instead of number of entries: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_crypto_list with valid data\n");

	if (knet_handle_get_crypto_list(knet_h, crypto_list, &crypto_list_entries1) < 0) {
		printf("knet_handle_get_crypto_list failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (crypto_list_entries != crypto_list_entries1) {
		printf("knet_handle_get_crypto_list returned a different number of entries: %d, %d\n",
		       (int)crypto_list_entries, (int)crypto_list_entries1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	for (i=0; i<crypto_list_entries; i++) {
		printf("Detected crypto: %s\n", crypto_list[i]);
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
