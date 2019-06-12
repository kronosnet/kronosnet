/*
 * Copyright (C) 2016-2019 Red Hat, Inc.  All rights reserved.
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
#include "link.h"
#include "netutils.h"
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	struct sockaddr_storage src, dst;
	struct knet_link_status status;

	if (make_local_sockaddr(&src, 0) < 0) {
		printf("Unable to convert src to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (make_local_sockaddr(&dst, 1) < 0) {
		printf("Unable to convert dst to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_link_get_status incorrect knet_h\n");

	memset(&status, 0, sizeof(struct knet_link_status));

	if ((!knet_link_get_status(NULL, 1, 0, &status, sizeof(struct knet_link_status))) || (errno != EINVAL)) {
		printf("knet_link_get_status accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_link_get_status with unconfigured host_id\n");

	if ((!knet_link_get_status(knet_h, 1, 0, &status, sizeof(struct knet_link_status))) || (errno != EINVAL)) {
		printf("knet_link_get_status accepted invalid host_id or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_get_status with incorrect linkid\n");

	if (knet_host_add(knet_h, 1) < 0) {
		printf("Unable to add host_id 1: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((!knet_link_get_status(knet_h, 1, KNET_MAX_LINK, &status, sizeof(struct knet_link_status))) || (errno != EINVAL)) {
		printf("knet_link_get_status accepted invalid linkid or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_get_status with incorrect status\n");

	if ((!knet_link_get_status(knet_h, 1, 0, NULL, 0)) || (errno != EINVAL)) {
		printf("knet_link_get_status accepted invalid status or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_get_status with unconfigured link\n");

	if ((!knet_link_get_status(knet_h, 1, 0, &status, sizeof(struct knet_link_status))) || (errno != EINVAL)) {
		printf("knet_link_get_status accepted unconfigured link or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_get_status with correct values\n");

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0) < 0) {
		printf("Unable to configure link: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_get_status(knet_h, 1, 0, &status, sizeof(struct knet_link_status)) < 0) {
		printf("knet_link_get_status failed: %s\n", strerror(errno));
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
	test();

	return PASS;
}
