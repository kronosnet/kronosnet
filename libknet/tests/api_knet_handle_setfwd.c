/*
 * Copyright (C) 2016-2025 Red Hat, Inc.  All rights reserved.
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

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int logfds[2];
	int res;

	printf("Test knet_handle_setfwd with invalid knet_h\n");

	if ((!knet_handle_setfwd(NULL, 0)) || (errno != EINVAL)) {
		printf("knet_handle_setfwd accepted invalid knet_h parameter\n");
		exit(FAIL);
	}

	setup_logpipes(logfds);

	printf("Test knet_handle_setfwd with invalid param (2) \n");
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);
	FAIL_ON_SUCCESS(knet_handle_setfwd(knet_h1, 2), EINVAL);

	printf("Test knet_handle_setfwd with valid param (1) \n");
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));

	if (knet_h1->enabled != 1) {
		printf("knet_handle_setfwd failed to set correct value");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_setfwd with valid param (0) \n");
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 0));

	if (knet_h1->enabled != 0) {
		printf("knet_handle_setfwd failed to set correct value");
		CLEAN_EXIT(FAIL);
	}

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
