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
	uint8_t onwire_min_ver, onwire_max_ver, onwire_ver;

	printf("Test knet_handle_get_onwire_ver incorrect knet_h\n");

	if ((!knet_handle_get_onwire_ver(NULL, 1, &onwire_min_ver, &onwire_max_ver, &onwire_ver)) || (errno != EINVAL)) {
		printf("knet_handle_get_onwire_ver accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_handle_get_onwire_ver with invalid host_id\n");

	if ((!knet_handle_get_onwire_ver(knet_h, 199, &onwire_min_ver, &onwire_max_ver, &onwire_ver)) || (errno != EINVAL)) {
		printf("knet_handle_get_onwire_ver accepted invalid onwire_min_ver or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);
	printf("Test knet_handle_get_onwire_ver with invalid onwire_min_ver\n");

	if ((!knet_handle_get_onwire_ver(knet_h, knet_h->host_id, NULL, &onwire_max_ver, &onwire_ver)) || (errno != EINVAL)) {
		printf("knet_handle_get_onwire_ver accepted invalid onwire_min_ver or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_onwire_ver with invalid onwire_max_ver\n");

	if ((!knet_handle_get_onwire_ver(knet_h, knet_h->host_id, &onwire_min_ver, NULL, &onwire_ver)) || (errno != EINVAL)) {
		printf("knet_handle_get_onwire_ver accepted invalid onwire_max_ver or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_onwire_ver with invalid onwire_ver\n");

	if ((!knet_handle_get_onwire_ver(knet_h, knet_h->host_id, &onwire_min_ver, &onwire_max_ver, NULL)) || (errno != EINVAL)) {
		printf("knet_handle_get_onwire_ver accepted invalid onwire_ver or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_onwire_ver with valid data\n");

	if (knet_handle_get_onwire_ver(knet_h, knet_h->host_id, &onwire_min_ver, &onwire_max_ver, &onwire_ver) < 0) {
		printf("knet_handle_get_onwire_ver accepted invalid onwire_ver or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	if (onwire_min_ver != knet_h->onwire_min_ver) {
		printf("knet_handle_get_onwire_ver returned invalid onwire_min_ver\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	if (onwire_max_ver != knet_h->onwire_max_ver) {
		printf("knet_handle_get_onwire_ver returned invalid onwire_max_ver\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	if (onwire_ver != knet_h->onwire_ver) {
		printf("knet_handle_get_onwire_ver returned invalid onwire_ver\n");
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
