/*
 * Copyright (C) 2016-2026 Red Hat, Inc.  All rights reserved.
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

#define TEST_NAME "api_knet_link_set_enable"

static void test_udp(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	struct sockaddr_storage src, dst;

	logfd = start_logging(stdout);

	FAIL_ON_ERR(make_local_sockaddr(&src, 0, logfd));

	FAIL_ON_ERR(make_local_sockaddr(&dst, 1, logfd));

	log_test(logfd, "Test knet_link_set_enable incorrect knet_h");

	FAIL_ON_SUCCESS(knet_link_set_enable(NULL, 1, 0, 1), EINVAL);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_set_enable with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, 0, 1), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with incorrect linkid");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, KNET_MAX_LINK, 1), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with unconfigured link");
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, 0, 1), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with incorrect values");
	FAIL_ON_ERR(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0));
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, 0, 2), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with correct values (1)");
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	if (knet_h1->host_index[1]->link[0].status.enabled != 1) {
		log_test(logfd, "knet_link_set_enable failed to set correct values");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_link_set_enable with correct values (0)");
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 0));
	if (knet_h1->host_index[1]->link[0].status.enabled != 0) {
		log_test(logfd, "knet_link_set_enable failed to set correct values");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

#ifdef HAVE_NETINET_SCTP_H
static void test_sctp(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	struct sockaddr_storage src, dst;

	logfd = start_logging(stdout);

	if (make_local_sockaddr(&src, 0, logfd) < 0) {
		log_test(logfd, "Unable to convert src to sockaddr: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	if (make_local_sockaddr(&dst, 1, logfd) < 0) {
		log_test(logfd, "Unable to convert dst to sockaddr: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_link_set_enable incorrect knet_h");

	FAIL_ON_SUCCESS(knet_link_set_enable(NULL, 1, 0, 1), EINVAL);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_set_enable with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, 0, 1), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with incorrect linkid");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, KNET_MAX_LINK, 1), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with unconfigured link");
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, 0, 1), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with incorrect values");
	if (knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_SCTP, &src, &dst, 0) < 0) {
		log_test(logfd, "Unable to configure link: %s", strerror(errno));
		TEST_EXIT_CLEAN(SKIP);
	}
	FAIL_ON_SUCCESS(knet_link_set_enable(knet_h1, 1, 0, 2), EINVAL);

	log_test(logfd, "Test knet_link_set_enable with correct values (1)");
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	if (knet_h1->host_index[1]->link[0].status.enabled != 1) {
		log_test(logfd, "knet_link_set_enable failed to set correct values");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Wait 2 seconds for sockets to connect");
	test_sleep(logfd, 2);

	log_test(logfd, "Test knet_link_set_enable with correct values (0)");
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 0));
	if (knet_h1->host_index[1]->link[0].status.enabled != 0) {
		log_test(logfd, "knet_link_set_enable failed to set correct values");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}
#endif

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet link set enable\n", TEST_NAME);

	printf("Testing with UDP\n");

	test_udp();

#ifdef HAVE_NETINET_SCTP_H
	printf("Testing with SCTP\n");

	test_sctp();
#else
	printf("Skipping SCTP test. Protocol not supported in this build\n");
#endif

	TEST_EXIT(PASS);
}
