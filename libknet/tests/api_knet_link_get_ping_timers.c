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
#include "link.h"
#include "netutils.h"
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	struct sockaddr_storage src, dst;
	time_t interval = 0, timeout = 0;
	unsigned int precision = 0;

	memset(&src, 0, sizeof(struct sockaddr_storage));

	if (knet_strtoaddr("127.0.0.1", "50000", &src, sizeof(struct sockaddr_storage)) < 0) {
		printf("Unable to convert src to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	memset(&dst, 0, sizeof(struct sockaddr_storage));

	if (knet_strtoaddr("127.0.0.1", "50001", &dst, sizeof(struct sockaddr_storage)) < 0) {
		printf("Unable to convert dst to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_link_get_ping_timers incorrect knet_h\n");

	if ((!knet_link_get_ping_timers(NULL, 1, 0, &interval, &timeout, &precision)) || (errno != EINVAL)) {
		printf("knet_link_get_ping_timers accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
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

	printf("Test knet_link_get_ping_timers with unconfigured host_id\n");

	if ((!knet_link_get_ping_timers(knet_h, 1, 0, &interval, &timeout, &precision)) || (errno != EINVAL)) {
		printf("knet_link_get_ping_timers accepted invalid host_id or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_get_ping_timers with incorrect linkid\n");

	if (knet_host_add(knet_h, 1) < 0) {
		printf("Unable to add host_id 1: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((!knet_link_get_ping_timers(knet_h, 1, KNET_MAX_LINK, &interval, &timeout, &precision)) || (errno != EINVAL)) {
		printf("knet_link_get_ping_timers accepted invalid linkid or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_get_ping_timers with incorrect interval\n");

	if ((!knet_link_get_ping_timers(knet_h, 1, 0, NULL, &timeout, &precision)) || (errno != EINVAL)) {
		printf("knet_link_get_ping_timers accepted invalid interval or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_get_ping_timers with incorrect timeout\n");

	if ((!knet_link_get_ping_timers(knet_h, 1, 0, &interval, NULL, &precision)) || (errno != EINVAL)) {
		printf("knet_link_get_ping_timers accepted invalid timeout or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_get_ping_timers with incorrect interval\n");

	if ((!knet_link_get_ping_timers(knet_h, 1, 0, &interval, &timeout, NULL)) || (errno != EINVAL)) {
		printf("knet_link_get_ping_timers accepted invalid interval or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_get_ping_timers with unconfigured link\n");

	if ((!knet_link_get_ping_timers(knet_h, 1, 0, &interval, &timeout, &precision)) || (errno != EINVAL)) {
		printf("knet_link_get_ping_timers accepted unconfigured link or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_get_ping_timers with correct values\n");

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, &dst) < 0) {
		printf("Unable to configure link: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_get_ping_timers(knet_h, 1, 0, &interval, &timeout, &precision) < 0) {
		printf("knet_link_get_ping_timers failed: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("DEFAULT: int: %ld timeout: %ld prec: %u\n", interval, timeout, precision);

	if ((interval != KNET_LINK_DEFAULT_PING_INTERVAL) ||
	    (timeout != KNET_LINK_DEFAULT_PING_TIMEOUT) ||
	    (precision != KNET_LINK_DEFAULT_PING_PRECISION)) {
		printf("knet_link_get_ping_timers failed to set values\n");
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	knet_link_clear_config(knet_h, 1, 0);
	knet_host_remove(knet_h, 1);
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
