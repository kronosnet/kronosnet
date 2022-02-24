/*
 * Copyright (C) 2016-2022 Red Hat, Inc.  All rights reserved.
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

#define TESTNODES 1
static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int logfds[2];
	int res;

	setup_logpipes(logfds);

	printf("Test knet_handle_free with invalid knet_h (part 1)\n");
	if ((!knet_handle_free(NULL)) || (errno != EINVAL)) {
		printf("knet_handle_free failed to detect invalid parameter\n");
		exit(FAIL);
	}

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_free with one host configured\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));

	if ((!knet_handle_free(knet_h1)) || (errno != EBUSY)) {
		CLEAN_EXIT(FAIL);
	}

	FAIL_ON_ERR(knet_host_remove(knet_h1, 1));

	printf("Test knet_handle_free with invalid knet_h (part 2)\n");
	FAIL_ON_SUCCESS(knet_handle_free(knet_h1 + 1), EINVAL);

	FAIL_ON_ERR(knet_handle_free(knet_h1));

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
