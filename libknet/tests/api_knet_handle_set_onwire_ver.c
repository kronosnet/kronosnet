/*
 * Copyright (C) 2020-2022 Red Hat, Inc.  All rights reserved.
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
	int res;
	int logfds[2];

	printf("Test knet_handle_set_onwire_ver incorrect knet_h\n");

	if ((!knet_handle_set_onwire_ver(NULL, 1)) || (errno != EINVAL)) {
		printf("knet_handle_set_onwire_ver accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	knet_h1->onwire_min_ver = 2;
	knet_h1->onwire_max_ver = 3;

	printf("Test knet_handle_set_onwire_ver with invalid onwire_ver (1)\n");
	FAIL_ON_SUCCESS(knet_handle_set_onwire_ver(knet_h1, 1), EINVAL);

	printf("Test knet_handle_set_onwire_ver with invalid onwire_ver (4)\n");
	FAIL_ON_SUCCESS(knet_handle_set_onwire_ver(knet_h1, 4), EINVAL);

	printf("Test knet_handle_set_onwire_ver with valid onwire_ver (2)\n");
	if (knet_handle_set_onwire_ver(knet_h1, 2) < 0) {
		printf("knet_handle_set_onwire_ver did not accepted valid onwire_ver\n");
		CLEAN_EXIT(FAIL);
	}

	if (knet_h1->onwire_force_ver != 2) {
		printf("knet_handle_set_onwire_ver did not set correct onwire_ver\n");
		CLEAN_EXIT(FAIL);
	}


	printf("Test knet_handle_set_onwire_ver reset (0)\n");
	FAIL_ON_ERR(knet_handle_set_onwire_ver(knet_h1, 0));

	if (knet_h1->onwire_force_ver != 0) {
		printf("knet_handle_set_onwire_ver did not set correct onwire_ver\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
