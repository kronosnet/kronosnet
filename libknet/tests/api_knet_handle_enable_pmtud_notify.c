/*
 * Copyright (C) 2016-2019 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
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

static int private_data;

static void pmtud_notify(void *priv_data,
			 unsigned int data_mtu)
{
	return;
}

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];

	printf("Test knet_handle_enable_pmtud_notify incorrect knet_h\n");

	if ((!knet_handle_enable_pmtud_notify(NULL, NULL, pmtud_notify)) || (errno != EINVAL)) {
		printf("knet_handle_enable_pmtud_notify accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_handle_enable_pmtud_notify with no private_data\n");

	if (knet_handle_enable_pmtud_notify(knet_h, NULL, pmtud_notify) < 0) {
		printf("knet_handle_enable_pmtud_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->pmtud_notify_fn_private_data != NULL) {
		printf("knet_handle_enable_pmtud_notify failed to unset private_data");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);

	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_enable_pmtud_notify with private_data\n");

	if (knet_handle_enable_pmtud_notify(knet_h, &private_data, NULL) < 0) {
		printf("knet_handle_enable_pmtud_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->pmtud_notify_fn_private_data != &private_data) {
		printf("knet_handle_enable_pmtud_notify failed to set private_data");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);

	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_enable_pmtud_notify with no pmtud_notify fn\n");

	if (knet_handle_enable_pmtud_notify(knet_h, NULL, NULL) < 0) {
		printf("knet_handle_enable_pmtud_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->pmtud_notify_fn != NULL) {
		printf("knet_handle_enable_pmtud_notify failed to unset pmtud_notify fn");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);

	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_enable_pmtud_notify with pmtud_notify fn\n");

	if (knet_handle_enable_pmtud_notify(knet_h, NULL, pmtud_notify) < 0) {
		printf("knet_handle_enable_pmtud_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->pmtud_notify_fn != &pmtud_notify) {
		printf("knet_handle_enable_pmtud_notify failed to set pmtud_notify fn");
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
