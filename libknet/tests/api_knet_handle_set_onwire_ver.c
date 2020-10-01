/*
 * Copyright (C) 2020 Red Hat, Inc.  All rights reserved.
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
	knet_handle_t knet_h;
	int logfds[2];

	printf("Test knet_handle_set_onwire_ver incorrect knet_h\n");

	if ((!knet_handle_set_onwire_ver(NULL, 1)) || (errno != EINVAL)) {
		printf("knet_handle_set_onwire_ver accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	knet_h->onwire_min_ver = 2;
	knet_h->onwire_max_ver = 3;

	printf("Test knet_handle_set_onwire_ver with invalid onwire_ver (1)\n");

	if ((!knet_handle_set_onwire_ver(knet_h, 1)) || (errno != EINVAL)) {
		printf("knet_handle_set_onwire_ver accepted invalid onwire_ver or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_set_onwire_ver with invalid onwire_ver (4)\n");

	if ((!knet_handle_set_onwire_ver(knet_h, 4)) || (errno != EINVAL)) {
		printf("knet_handle_set_onwire_ver accepted invalid onwire_ver or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_set_onwire_ver with valid onwire_ver (2)\n");

	if (knet_handle_set_onwire_ver(knet_h, 2) < 0) {
		printf("knet_handle_set_onwire_ver did not accepted valid onwire_ver\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->onwire_force_ver != 2) {
		printf("knet_handle_set_onwire_ver did not set correct onwire_ver\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_set_onwire_ver reset (0)\n");

	if (knet_handle_set_onwire_ver(knet_h, 0) < 0) {
		printf("knet_handle_set_onwire_ver did not accept valid onwire_ver\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	if (knet_h->onwire_force_ver != 0) {
		printf("knet_handle_set_onwire_ver did not set correct onwire_ver\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
