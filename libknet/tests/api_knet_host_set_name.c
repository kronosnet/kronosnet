/*
 * Copyright (C) 2016-2018 Red Hat, Inc.  All rights reserved.
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
	char longhostname[KNET_MAX_HOST_LEN+2];

	printf("Test knet_host_set_name incorrect knet_h\n");

	if ((!knet_host_set_name(NULL, 1, "test")) || (errno != EINVAL)) {
		printf("knet_host_set_name accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_set_name with incorrect hostid 1\n");

	if ((!knet_host_set_name(knet_h, 2, "test")) || (errno != EINVAL)) {
		printf("knet_host_set_name accepted invalid host_id or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_set_name with correct values\n");

	if (knet_host_add(knet_h, 1) < 0) {
		printf("knet_host_add failed error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_host_set_name(knet_h, 1, "test") < 0) {
		printf("knet_host_set_name failed: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (strcmp("test", knet_h->host_index[1]->name)) {
		printf("knet_host_set_name failed to copy name\n");
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_set_name with correct values (name change)\n");

	if (knet_host_set_name(knet_h, 1, "tes") < 0) {
		printf("knet_host_set_name failed: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (strcmp("tes", knet_h->host_index[1]->name)) {
		printf("knet_host_set_name failed to change name\n");
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_set_name with NULL name\n");

	if ((!knet_host_set_name(knet_h, 1, NULL)) || (errno != EINVAL)) {
		printf("knet_host_set_name accepted invalid name or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_host_set_name with duplicate name\n");

	if (knet_host_add(knet_h, 2) < 0) {
		printf("knet_host_add failed error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((!knet_host_set_name(knet_h, 2, "tes")) || (errno != EEXIST)) {
		printf("knet_host_set_name accepted duplicated name or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 2);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	knet_host_remove(knet_h, 2);
	flush_logs(logfds[0], stdout);

	printf("Test knet_host_set_name with (too) long name\n");

	memset(longhostname, 'a', sizeof(longhostname));
	longhostname[KNET_MAX_HOST_LEN] = '\0';

	if ((!knet_host_set_name(knet_h, 1, longhostname)) || (errno != EINVAL)) {
		printf("knet_host_set_name accepted invalid (too long) name or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

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
