/*
 * Copyright (C) 2017-2025 Red Hat, Inc.  All rights reserved.
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
#include <sys/time.h>
#include <sys/resource.h>

#include "libknet.h"
#include "internals.h"

#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h[UINT8_MAX + 1];
	int logfds[2];
	int idx;

	setup_logpipes(logfds);

	for (idx = 0; idx < UINT8_MAX; idx++) {
		printf("Allocating %d\n", idx);
		knet_h[idx] = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG, 0);
		if (!knet_h[idx]) {
			printf("knet_handle_new[%d] failed: %s\n", idx, strerror(errno));
			flush_logs(logfds[0], stdout);
			close_logpipes(logfds);
			exit(FAIL);
		}
		flush_logs(logfds[0], stdout);
	}

	printf("forcing UINT8_T MAX\n");
	knet_h[UINT8_MAX] = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG, 0);
	if (knet_h[UINT8_MAX]) {
		printf("off by one somewhere\n");
		knet_handle_free(knet_h[UINT8_MAX]);
	}
	flush_logs(logfds[0], stdout);

	for (idx = 0; idx < UINT8_MAX; idx++) {
		printf("Freeing %d\n", idx);
		knet_handle_free(knet_h[idx]);
		flush_logs(logfds[0], stdout);
	}
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	if ((is_memcheck()) || (is_helgrind())) {
		return SKIP;
	}

	test();

	return PASS;
}
