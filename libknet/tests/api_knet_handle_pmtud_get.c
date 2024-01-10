/*
 * Copyright (C) 2016-2024 Red Hat, Inc.  All rights reserved.
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
	unsigned int data_mtu;

	printf("Test knet_handle_pmtud_get incorrect knet_h\n");

	if ((!knet_handle_pmtud_get(NULL, &data_mtu)) || (errno != EINVAL)) {
		printf("knet_handle_pmtud_get accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_pmtud_get with no data_mtu\n");
	FAIL_ON_SUCCESS(knet_handle_pmtud_get(knet_h1, NULL), EINVAL);

	FAIL_ON_ERR(knet_handle_pmtud_get(knet_h1, &data_mtu));

	if (knet_h1->data_mtu != data_mtu) {
		printf("knet_handle_pmtud_get failed to set the value\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
