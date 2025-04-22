/*
 * Copyright (C) 2020-2025 Red Hat, Inc.  All rights reserved.
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
	uint8_t onwire_min_ver, onwire_max_ver, onwire_ver;

	printf("Test knet_handle_get_onwire_ver incorrect knet_h\n");

	if ((!knet_handle_get_onwire_ver(NULL, 1, &onwire_min_ver, &onwire_max_ver, &onwire_ver)) || (errno != EINVAL)) {
		printf("knet_handle_get_onwire_ver accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_handle_get_onwire_ver with invalid host_id\n");
	FAIL_ON_SUCCESS(knet_handle_get_onwire_ver(knet_h1, 199, &onwire_min_ver, &onwire_max_ver, &onwire_ver), EINVAL);

	printf("Test knet_handle_get_onwire_ver with invalid onwire_min_ver\n");
	FAIL_ON_SUCCESS(knet_handle_get_onwire_ver(knet_h1, knet_h1->host_id, NULL, &onwire_max_ver, &onwire_ver), EINVAL);

	printf("Test knet_handle_get_onwire_ver with invalid onwire_max_ver\n");
	FAIL_ON_SUCCESS(knet_handle_get_onwire_ver(knet_h1, knet_h1->host_id, &onwire_min_ver, NULL, &onwire_ver), EINVAL);

	printf("Test knet_handle_get_onwire_ver with invalid onwire_ver\n");
	FAIL_ON_SUCCESS(knet_handle_get_onwire_ver(knet_h1, knet_h1->host_id, &onwire_min_ver, &onwire_max_ver, NULL), EINVAL);

	printf("Test knet_handle_get_onwire_ver with valid data\n");
	FAIL_ON_ERR(knet_handle_get_onwire_ver(knet_h1, knet_h1->host_id, &onwire_min_ver, &onwire_max_ver, &onwire_ver));

	if (onwire_min_ver != knet_h1->onwire_min_ver) {
		printf("knet_handle_get_onwire_ver returned invalid onwire_min_ver\n");
		CLEAN_EXIT(FAIL);
	}

	if (onwire_max_ver != knet_h1->onwire_max_ver) {
		printf("knet_handle_get_onwire_ver returned invalid onwire_max_ver\n");
		CLEAN_EXIT(FAIL);
	}

	if (onwire_ver != knet_h1->onwire_ver) {
		printf("knet_handle_get_onwire_ver returned invalid onwire_ver\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
