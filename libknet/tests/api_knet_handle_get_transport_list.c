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
	struct knet_transport_info transport_list[KNET_MAX_TRANSPORTS];
	size_t transport_list_entries;
	size_t i, expected_count;

	memset(transport_list, 0, sizeof(transport_list));

	printf("Test knet_handle_get_transport_list with incorrect knet_h\n");

	if (!knet_handle_get_transport_list(NULL, transport_list, &transport_list_entries) || (errno != EINVAL)) {
		printf("knet_handle_get_transport_list accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
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

	printf("Test knet_handle_get_transport_list with no transport_list\n");

	if ((!knet_handle_get_transport_list(knet_h, NULL, &transport_list_entries)) || (errno != EINVAL)) {
		printf("knet_handle_get_transport_list accepted invalid datafd or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_transport_list with no channel\n");

	if ((!knet_handle_get_transport_list(knet_h, transport_list, NULL)) || (errno != EINVAL)) {
		printf("knet_handle_get_transport_list accepted invalid transport_list_entries or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_handle_get_transport_list with valid data\n");

	if (knet_handle_get_transport_list(knet_h, transport_list, &transport_list_entries) < 0) {
		printf("knet_handle_get_transport_list failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	for (i=0; i<transport_list_entries; i++) {
		printf("Detected transport: %s id: %d properties: %u\n",
			transport_list[i].name, transport_list[i].id, transport_list[i].properties);
	}

	expected_count = KNET_MAX_TRANSPORTS;
#ifndef HAVE_NETINET_SCTP_H
	expected_count--;
#endif

	if (transport_list_entries != expected_count) {
		printf("Error! expected: %zu transports, got: %zu\n", expected_count, transport_list_entries);
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
	need_root();

	test();

	return PASS;
}
