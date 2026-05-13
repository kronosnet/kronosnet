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

#define TEST_NAME "api_knet_link_get_config"

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	struct sockaddr_storage lo, get_src, get_dst;
	uint8_t dynamic = 0, transport = 0;
	uint64_t flags;

	log_test(logfd, "Test knet_link_get_config incorrect knet_h");

	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));

	if ((!knet_link_get_config(NULL, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags)) || (errno != EINVAL)) {
		log_test(logfd, "knet_link_get_config accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_get_config with unconfigured host_id");
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags), EINVAL);

	log_test(logfd, "Test knet_link_get_config with incorrect linkid");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, KNET_MAX_LINK, &transport, &get_src, &get_dst, &dynamic, &flags), EINVAL);

	log_test(logfd, "Test knet_link_get_config with incorrect src_addr");
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, &transport, NULL, &get_dst, &dynamic, &flags), EINVAL);

	log_test(logfd, "Test knet_link_get_config with incorrect dynamic");
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, NULL, &flags), EINVAL);

	log_test(logfd, "Test knet_link_get_config with unconfigured link");
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags), EINVAL);

	log_test(logfd, "Test knet_link_get_config with incorrect dst_addr");
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, NULL, &dynamic, &flags), EINVAL);

	if (dynamic) {
		log_test(logfd, "knet_link_get_config returned invalid dynamic status");
		TEST_EXIT_CLEAN(FAIL);
	}


	log_test(logfd, "Test knet_link_get_config with correct parameters for static link");
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_ERR(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags));

	if (transport != KNET_TRANSPORT_UDP) {
		log_test(logfd, "knet_link_get_config returned incorrect transport: %d", transport);
		TEST_EXIT_CLEAN(FAIL);
	}

	if ((dynamic) ||
	    (memcmp(&lo, &get_src, sizeof(struct sockaddr_storage))) ||
	    (memcmp(&lo, &get_dst, sizeof(struct sockaddr_storage)))) {
		log_test(logfd, "knet_link_get_config returned invalid data");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_link_get_config with correct parameters for dynamic link");
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 1, &lo, logfd));
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_ERR(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags));

	if ((!dynamic) ||
	    (memcmp(&lo, &get_src, sizeof(struct sockaddr_storage)))) {
		log_test(logfd, "knet_link_get_config returned invalid data");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_link_get_config NULL transport ptr");
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, NULL, &get_src, &get_dst, &dynamic, &flags), EINVAL);

	log_test(logfd, "Test knet_link_get_config with flags");
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, KNET_LINK_FLAG_TRAFFICHIPRIO, AF_INET, 1, &lo, logfd));
	FAIL_ON_ERR(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags));
	if (flags != KNET_LINK_FLAG_TRAFFICHIPRIO) {
		log_test(logfd, "knet_link_get_config returned no flags");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet link get config\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
