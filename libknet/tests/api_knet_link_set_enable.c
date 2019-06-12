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

static void test_udp(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	struct sockaddr_storage src, dst;

	if (make_local_sockaddr(&src, 0) < 0) {
		printf("Unable to convert src to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (make_local_sockaddr(&dst, 1) < 0) {
		printf("Unable to convert dst to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_link_set_enable incorrect knet_h\n");

	if ((!knet_link_set_enable(NULL, 1, 0, 1)) || (errno != EINVAL)) {
		printf("knet_link_set_enable accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_link_set_enable with unconfigured host_id\n");

	if ((!knet_link_set_enable(knet_h, 1, 0, 1)) || (errno != EINVAL)) {
		printf("knet_link_set_enable accepted invalid host_id or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_enable with incorrect linkid\n");

	if (knet_host_add(knet_h, 1) < 0) {
		printf("Unable to add host_id 1: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((!knet_link_set_enable(knet_h, 1, KNET_MAX_LINK, 1)) || (errno != EINVAL)) {
		printf("knet_link_set_enable accepted invalid linkid or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_enable with unconfigured link\n");

	if ((!knet_link_set_enable(knet_h, 1, 0, 1)) || (errno != EINVAL)) {
		printf("knet_link_set_enable accepted unconfigured link or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_enable with incorrect values\n");

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0) < 0) {
		printf("Unable to configure link: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((!knet_link_set_enable(knet_h, 1, 0, 2)) || (errno != EINVAL)) {
		printf("knet_link_set_enable accepted incorrect value for enabled or returned incorrect error: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_enable with correct values (1)\n");

	if (knet_link_set_enable(knet_h, 1, 0, 1) < 0) {
		printf("knet_link_set_enable failed: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->host_index[1]->link[0].status.enabled != 1) {
		printf("knet_link_set_enable failed to set correct values\n");
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Test knet_link_set_enable with correct values (0)\n");

	if (knet_link_set_enable(knet_h, 1, 0, 0) < 0) {
		printf("knet_link_set_enable failed: %s\n", strerror(errno));
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->host_index[1]->link[0].status.enabled != 0) {
		printf("knet_link_set_enable failed to set correct values\n");
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	knet_link_set_enable(knet_h, 1, 0, 0);
	knet_link_clear_config(knet_h, 1, 0);
	knet_host_remove(knet_h, 1);
	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

#ifdef HAVE_NETINET_SCTP_H
static void test_sctp(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	struct sockaddr_storage src, dst;

	if (make_local_sockaddr(&src, 0) < 0) {
		printf("Unable to convert src to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (make_local_sockaddr(&dst, 1) < 0) {
		printf("Unable to convert dst to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_link_set_enable incorrect knet_h\n");

	if ((!knet_link_set_enable(NULL, 1, 0, 1)) || (errno != EINVAL)) {
		printf("knet_link_set_enable accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_link_set_enable with unconfigured host_id\n");

	if ((!knet_link_set_enable(knet_h, 1, 0, 1)) || (errno != EINVAL)) {
		printf("knet_link_set_enable accepted invalid host_id or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_enable with incorrect linkid\n");

	if (knet_host_add(knet_h, 1) < 0) {
		printf("Unable to add host_id 1: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((!knet_link_set_enable(knet_h, 1, KNET_MAX_LINK, 1)) || (errno != EINVAL)) {
		printf("knet_link_set_enable accepted invalid linkid or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_enable with unconfigured link\n");

	if ((!knet_link_set_enable(knet_h, 1, 0, 1)) || (errno != EINVAL)) {
		printf("knet_link_set_enable accepted unconfigured link or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_enable with incorrect values\n");

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_SCTP, &src, &dst, 0) < 0) {
		int exit_status = errno == EPROTONOSUPPORT ? SKIP : FAIL;
		printf("Unable to configure link: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(exit_status);
	}

	if ((!knet_link_set_enable(knet_h, 1, 0, 2)) || (errno != EINVAL)) {
		printf("knet_link_set_enable accepted incorrect value for enabled or returned incorrect error: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_enable with correct values (1)\n");

	if (knet_link_set_enable(knet_h, 1, 0, 1) < 0) {
		printf("knet_link_set_enable failed: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->host_index[1]->link[0].status.enabled != 1) {
		printf("knet_link_set_enable failed to set correct values\n");
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Wait 2 seconds for sockets to connect\n");
	sleep(2);

	printf("Test knet_link_set_enable with correct values (0)\n");

	if (knet_link_set_enable(knet_h, 1, 0, 0) < 0) {
		printf("knet_link_set_enable failed: %s\n", strerror(errno));
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->host_index[1]->link[0].status.enabled != 0) {
		printf("knet_link_set_enable failed to set correct values\n");
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	knet_link_set_enable(knet_h, 1, 0, 0);
	knet_link_clear_config(knet_h, 1, 0);
	knet_host_remove(knet_h, 1);
	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}
#endif

int main(int argc, char *argv[])
{
	printf("Testing with UDP\n");

	test_udp();

#ifdef HAVE_NETINET_SCTP_H
	printf("Testing with SCTP\n");

	test_sctp();
#else
	printf("Skipping SCTP test. Protocol not supported in this build\n");
#endif

	return PASS;
}
