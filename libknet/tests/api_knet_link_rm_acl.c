/*
 * Copyright (C) 2019-2021 Red Hat, Inc.  All rights reserved.
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
#include <inttypes.h>

#include "libknet.h"

#include "internals.h"
#include "netutils.h"
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	struct knet_host *host;
	struct knet_link *link;
	struct sockaddr_storage lo, lo6;

	if (make_local_sockaddr(&lo, 0) < 0) {
		printf("Unable to convert loopback to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (make_local_sockaddr6(&lo6, 0) < 0) {
		printf("Unable to convert loopback to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_link_rm_acl incorrect knet_h\n");

	if ((!knet_link_rm_acl(NULL, 1, 0, &lo, &lo, CHECK_TYPE_ADDRESS, CHECK_ACCEPT)) || (errno != EINVAL)) {
		printf("knet_link_rm_acl accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_link_rm_acl with unconfigured host\n");

	if ((!knet_link_rm_acl(knet_h, 1, 0, &lo, &lo, CHECK_TYPE_ADDRESS, CHECK_ACCEPT)) || (errno != EINVAL)) {
		printf("knet_link_rm_acl accepted unconfigured host or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_rm_acl with unconfigured link\n");

	if (knet_host_add(knet_h, 1) < 0) {
		printf("knet_host_add failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((!knet_link_rm_acl(knet_h, 1, 0, &lo, &lo, CHECK_TYPE_ADDRESS, CHECK_ACCEPT)) || (errno != EINVAL)) {
		printf("knet_link_rm_acl accepted unconfigured link or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_rm_acl with invalid link\n");

	if ((!knet_link_rm_acl(knet_h, 1, KNET_MAX_LINK, &lo, &lo, CHECK_TYPE_ADDRESS, CHECK_ACCEPT)) || (errno != EINVAL)) {
		printf("knet_link_rm_acl accepted invalid link or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_rm_acl with invalid ss1\n");

	if ((!knet_link_rm_acl(knet_h, 1, 0, NULL, &lo, CHECK_TYPE_ADDRESS, CHECK_ACCEPT)) || (errno != EINVAL)) {
		printf("knet_link_rm_acl accepted invalid ss1 or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_rm_acl with invalid ss2\n");

	if ((!knet_link_rm_acl(knet_h, 1, 0, &lo, NULL, CHECK_TYPE_RANGE, CHECK_ACCEPT)) || (errno != EINVAL)) {
		printf("knet_link_rm_acl accepted invalid ss2 or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_rm_acl with non matching families\n");

	if ((!knet_link_rm_acl(knet_h, 1, 0, &lo, &lo6, CHECK_TYPE_RANGE, CHECK_ACCEPT)) || (errno != EINVAL)) {
		printf("knet_link_rm_acl accepted non matching families or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_rm_acl with wrong check_type\n");

	if ((!knet_link_rm_acl(knet_h, 1, 0, &lo, &lo, CHECK_TYPE_RANGE + CHECK_TYPE_MASK + CHECK_TYPE_ADDRESS + 1, CHECK_ACCEPT)) || (errno != EINVAL)) {
		printf("knet_link_rm_acl accepted incorrect check_type or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_rm_acl with wrong acceptreject\n");

	if ((!knet_link_rm_acl(knet_h, 1, 0, &lo, &lo, CHECK_TYPE_ADDRESS, CHECK_ACCEPT + CHECK_REJECT + 1)) || (errno != EINVAL)) {
		printf("knet_link_rm_acl accepted incorrect check_type or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_rm_acl with point to point link\n");

	if (_knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo) < 0) {
		printf("Unable to configure link: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((!knet_link_rm_acl(knet_h, 1, 0, &lo, &lo, CHECK_TYPE_ADDRESS, CHECK_ACCEPT)) || (errno != EINVAL)) {
		printf("knet_link_rm_acl accepted point ot point link or returned incorrect error: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	knet_link_clear_config(knet_h, 1, 0);

	printf("Test knet_link_rm_acl with dynamic link\n");

	if (_knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 1, &lo) < 0) {
		printf("Unable to configure link: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	host = knet_h->host_index[1];
	link = &host->link[0];

	if (knet_h->knet_transport_fd_tracker[link->outsock].access_list_match_entry_head) {
		printf("match list not empty!");
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_add_acl(knet_h, 1, 0, &lo, &lo, CHECK_TYPE_ADDRESS, CHECK_ACCEPT) < 0) {
		printf("Failed to add an access list: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_rm_acl(knet_h, 1, 0, &lo, &lo, CHECK_TYPE_ADDRESS, CHECK_ACCEPT) < 0) {
		printf("knet_link_rm_acl did not accept dynamic link error: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->knet_transport_fd_tracker[link->outsock].access_list_match_entry_head) {
		printf("match list NOT empty!");
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
