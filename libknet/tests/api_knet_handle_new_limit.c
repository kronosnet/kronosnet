/*
 * Copyright (C) 2017-2026 Red Hat, Inc.  All rights reserved.
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
	int logfd;
	knet_handle_t knet_h[UINT8_MAX + 1];
	unsigned int idx;

	logfd = start_logging(stdout);


	for (idx = 0; idx < UINT8_MAX; idx++) {
		log_test(logfd, "Allocating %d", idx);
		knet_h[idx] = knet_handle_new(1, logfd, KNET_LOG_DEBUG, 0);
		if (!knet_h[idx]) {
			log_test(logfd, "knet_handle_new[%d] failed: %s", idx, strerror(errno));
		stop_logging();
			exit(FAIL);
		}
	}

	log_test(logfd, "forcing UINT8_T MAX");
	knet_h[UINT8_MAX] = knet_handle_new(1, logfd, KNET_LOG_DEBUG, 0);
	if (knet_h[UINT8_MAX]) {
		log_test(logfd, "off by one somewhere");
		knet_handle_free(knet_h[UINT8_MAX]);
	}

	for (idx = 0; idx < UINT8_MAX; idx++) {
		log_test(logfd, "Freeing %d", idx);
		knet_handle_free(knet_h[idx]);
	}

	stop_logging();
}

int main(int argc, char *argv[])
{
	if ((is_memcheck()) || (is_helgrind())) {
		return SKIP;
	}

	test();

	return PASS;
}
