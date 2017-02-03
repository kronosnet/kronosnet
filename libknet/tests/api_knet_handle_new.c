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
#include <sys/time.h>
#include <sys/resource.h>

#include "libknet.h"
#include "internals.h"

#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h;
	struct rlimit cur;
	int logfds[2];

	printf("Test knet_handle_new hostid 1, no logging\n");

	knet_h = knet_handle_new(1, 0, 0);
	if (!knet_h) {
		printf("Unable to init knet_handle! err: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (knet_handle_free(knet_h) != 0) {
		printf("Unable to free knet_handle\n");
		exit(FAIL);
	}

	printf("Test knet_handle_new hostid -1, no logging\n");

	knet_h = knet_handle_new(-1, 0, 0);
	if (!knet_h) {
		printf("Unable to init knet_handle! err: %s\n", strerror(errno));
		exit(FAIL);
	}

	/*
	 * -1 == uint8_t 255
	 */

	if (knet_h->host_id != 255) {
		printf("host_id size might have changed!\n");
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	if (knet_handle_free(knet_h) != 0) {
		printf("Unable to free knet_handle\n");
		exit(FAIL);
	}

	if (getrlimit(RLIMIT_NOFILE, &cur) < 0) {
		printf("Unable to get current fd limit: %s\n", strerror(errno));
		exit(SKIP);
	}

	/*
	 * passing a bad fd and it should fail
	 */
	printf("Test knet_handle_new hostid 1, incorrect log_fd (-1)\n");

	knet_h = knet_handle_new(1, -1, 0);

	if ((!knet_h) && (errno != EINVAL)) {
		printf("knet_handle_new returned incorrect errno on incorrect log_fd\n");
		exit(FAIL);
	}

	if (knet_h) {
		printf("knet_handle_new accepted an incorrect (-1) log_fd\n");
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	/*
	 * passing a bad fd and it should fail
	 */
	printf("Test knet_handle_new hostid 1, incorrect log_fd (max_fd + 1)\n");

	knet_h = knet_handle_new(1, (int) cur.rlim_max, 0);

	if ((knet_h) || (errno != EINVAL)) {
		printf("knet_handle_new accepted an incorrect (max_fd + 1) log_fd or returned incorrect errno on incorrect log_fd: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		exit(FAIL);
	}

	setup_logpipes(logfds);

	printf("Test knet_handle_new hostid 1, proper log_fd, invalid log level (DEBUG + 1)\n");

	knet_h = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG + 1);

	if ((knet_h) || (errno != EINVAL)) {
		printf("knet_handle_new accepted an incorrect log level or returned incorrect errno on incorrect log level: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Test knet_handle_new hostid 1, proper log_fd, proper log level (DEBUG)\n");

	knet_h = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG);

	if (!knet_h) {
		printf("knet_handle_new failed: %s\n", strerror(errno));
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
