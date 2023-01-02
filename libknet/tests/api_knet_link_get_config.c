/*
 * Copyright (C) 2016-2023 Red Hat, Inc.  All rights reserved.
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
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	struct sockaddr_storage lo, get_src, get_dst;
	uint8_t dynamic = 0, transport = 0;
	uint64_t flags;

	printf("Test knet_link_get_config incorrect knet_h\n");

	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));

	if ((!knet_link_get_config(NULL, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags)) || (errno != EINVAL)) {
		printf("knet_link_get_config accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_link_get_config with unconfigured host_id\n");
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags), EINVAL);

	printf("Test knet_link_get_config with incorrect linkid\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, KNET_MAX_LINK, &transport, &get_src, &get_dst, &dynamic, &flags), EINVAL);

	printf("Test knet_link_get_config with incorrect src_addr\n");
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, &transport, NULL, &get_dst, &dynamic, &flags), EINVAL);

	printf("Test knet_link_get_config with incorrect dynamic\n");
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, NULL, &flags), EINVAL);

	printf("Test knet_link_get_config with unconfigured link\n");
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags), EINVAL);

	printf("Test knet_link_get_config with incorrect dst_addr\n");
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo));
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, NULL, &dynamic, &flags), EINVAL);

	if (dynamic) {
		printf("knet_link_get_config returned invalid dynamic status\n");
		CLEAN_EXIT(FAIL);
	}


	printf("Test knet_link_get_config with correct parameters for static link\n");
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_ERR(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags));

	if (transport != KNET_TRANSPORT_UDP) {
		printf("knet_link_get_config returned incorrect transport: %d\n", transport);
		CLEAN_EXIT(FAIL);
	}

	if ((dynamic) ||
	    (memcmp(&lo, &get_src, sizeof(struct sockaddr_storage))) ||
	    (memcmp(&lo, &get_dst, sizeof(struct sockaddr_storage)))) {
		printf("knet_link_get_config returned invalid data\n");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_link_get_config with correct parameters for dynamic link\n");
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 1, &lo));
	memset(&get_src, 0, sizeof(struct sockaddr_storage));
	memset(&get_dst, 0, sizeof(struct sockaddr_storage));
	FAIL_ON_ERR(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags));

	if ((!dynamic) ||
	    (memcmp(&lo, &get_src, sizeof(struct sockaddr_storage)))) {
		printf("knet_link_get_config returned invalid data\n");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_link_get_config NULL transport ptr\n");
	FAIL_ON_SUCCESS(knet_link_get_config(knet_h1, 1, 0, NULL, &get_src, &get_dst, &dynamic, &flags), EINVAL);

	printf("Test knet_link_get_config with flags\n");
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, KNET_LINK_FLAG_TRAFFICHIPRIO, AF_INET, 1, &lo));
	FAIL_ON_ERR(knet_link_get_config(knet_h1, 1, 0, &transport, &get_src, &get_dst, &dynamic, &flags));
	if (flags != KNET_LINK_FLAG_TRAFFICHIPRIO) {
		printf("knet_link_get_config returned no flags\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
