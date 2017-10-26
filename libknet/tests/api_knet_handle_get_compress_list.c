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
	const char *compress_list[16];
	size_t compress_list_entries;
	size_t compress_list_entries1;
	size_t i;

	memset(compress_list, 0, sizeof(compress_list));

	printf("Test knet_handle_get_compress_list with incorrect knet_h\n");

	if (!knet_handle_get_compress_list(NULL, compress_list, &compress_list_entries) || (errno != EINVAL)) {
		printf("knet_handle_get_compress_list accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
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

	printf("Test knet_handle_get_compress_list with no entries_list\n");

	if ((!knet_handle_get_compress_list(knet_h, compress_list, NULL)) || (errno != EINVAL)) {
		printf("knet_handle_get_compress_list accepted invalid list_entries or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_compress_list with no compress_list (get number of entries)\n");

	if (knet_handle_get_compress_list(knet_h, NULL, &compress_list_entries) < 0) {
		printf("knet_handle_get_compress_list returned error instead of number of entries: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_compress_list with valid data\n");

	if (knet_handle_get_compress_list(knet_h, compress_list, &compress_list_entries1) < 0) {
		printf("knet_handle_get_compress_list failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (compress_list_entries != compress_list_entries1) {
		printf("knet_handle_get_compress_list returned a different number of entries: %d, %d\n",
		       (int)compress_list_entries, (int)compress_list_entries1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	for (i=0; i<compress_list_entries; i++) {
		printf("Detected compress: %s\n", compress_list[i]);
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
