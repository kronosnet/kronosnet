/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
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

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];

	printf("Test knet_handle_pmtud_setfreq incorrect knet_h\n");

	if ((!knet_handle_pmtud_setfreq(NULL, 1)) || (errno != EINVAL)) {
		printf("knet_handle_pmtud_setfreq accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG);

	if (!knet_h) {
		printf("knet_handle_new failed: %s\n", strerror(errno));
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_pmtud_setfreq with 0 (incorrect)\n");
	if ((!knet_handle_pmtud_setfreq(NULL, 0)) || (errno != EINVAL)) {
		printf("knet_handle_pmtud_setfreq accepted invalid PTMUd freq or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_pmtud_setfreq with 86401 (incorrect)\n");
	if ((!knet_handle_pmtud_setfreq(NULL, 86401)) || (errno != EINVAL)) {
		printf("knet_handle_pmtud_setfreq accepted invalid PTMUd freq or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_pmtud_setfreq with 1 (correct)\n");
	if (knet_handle_pmtud_setfreq(knet_h, 1) < 0) {
		printf("knet_handle_pmtud_setfreq failed error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->pmtud_interval != 1) {
		printf("knet_handle_pmtud_setfreq failed to set the value\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	need_root();

	test();

	return PASS;
}
