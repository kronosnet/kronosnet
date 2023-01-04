/*
 * Copyright (C) 2016-2023 Red Hat, Inc.  All rights reserved.
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
#include "host.h"
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	struct knet_host_status status;

	printf("Test knet_host_get_status incorrect knet_h\n");

	memset(&status, 0, sizeof(struct knet_host_status));

	if ((!knet_host_get_status(NULL, 1, &status)) || (errno != EINVAL)) {
		printf("knet_host_get_status accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_host_get_status with unconfigured host_id\n");
	FAIL_ON_SUCCESS(knet_host_get_status(knet_h1, 1, &status), EINVAL);

	printf("Test knet_host_get_status with incorrect status\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_host_get_status(knet_h1, 1, NULL), EINVAL);

	printf("Test knet_host_get_status with correct values\n");
	FAIL_ON_ERR(knet_host_get_status(knet_h1, 1, &status));

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
