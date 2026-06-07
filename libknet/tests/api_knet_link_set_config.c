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
#include "links.h"
#include "netutils.h"
#include "test-common.h"

#define TEST_NAME "api_knet_link_set_config"

static void test(void)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	struct knet_host *host;
	struct knet_link *link;
	char lo_portstr[32];
	struct sockaddr_storage lo, lo6;
	struct sockaddr_in *lo_in = (struct sockaddr_in *)&lo;
	struct knet_link_status link_status;

	logfd = start_logging(stdout);

	FAIL_ON_ERR(make_local_sockaddr(&lo, -1, logfd));
	snprintf(lo_portstr, sizeof(lo_portstr), "%d", ntohs(lo_in->sin_port));

	log_test(logfd, "Test knet_link_set_config incorrect knet_h");

	FAIL_ON_SUCCESS(knet_link_set_config(NULL, 1, 0, KNET_TRANSPORT_UDP, &lo, &lo, 0), EINVAL);

	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_link_set_config with unconfigured host_id");
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, &lo, 0), EINVAL);

	log_test(logfd, "Test knet_link_set_config with bad transport type");
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_MAX_TRANSPORTS, &lo, &lo, 0), EINVAL);

	log_test(logfd, "Test knet_link_set_config with incorrect linkid");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, KNET_MAX_LINK, KNET_TRANSPORT_UDP, &lo, &lo, 0), EINVAL);

	log_test(logfd, "Test knet_link_set_config with incorrect src_addr");
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, NULL, &lo, 0), EINVAL);

	log_test(logfd, "Test knet_link_set_config with conflicting address families");
	FAIL_ON_ERR(make_local_sockaddr6(&lo6, -1, logfd));
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, &lo6, 0), EINVAL);

	log_test(logfd, "Test knet_link_set_config with dynamic dst_addr");
	FAIL_ON_ERR(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, NULL, 0));
	host = knet_h1->host_index[1];
	link = &host->link[0];
	if (link->access_list_match_entry_head) {
		log_test(logfd, "found access lists for dynamic dst_addr!");
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(knet_link_get_status(knet_h1, 1, 0, &link_status, sizeof(struct knet_link_status)));

	if ((link_status.enabled != 0) ||
	    (strcmp(link_status.src_ipaddr, "127.0.0.1")) ||
	    (strcmp(link_status.src_port, lo_portstr)) ||
	    (knet_h1->host_index[1]->link[0].dynamic != KNET_LINK_DYNIP)) {
		log_test(logfd, "knet_link_set_config failed to set configuration.");
		log_test(logfd, "saddr: %.246s", link_status.src_ipaddr);
		log_test(logfd, "sport: %s", link_status.src_port);
		log_test(logfd, "enabled: %d, dynamic: %u",
		       link_status.enabled, knet_h1->host_index[1]->link[0].dynamic);
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_link_set_config with dynamic link (0) and static link (1)");
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 1, KNET_TRANSPORT_UDP, &lo, &lo, 0), EINVAL);

	log_test(logfd, "Test knet_link_set_config with already configured link");
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, NULL, 0), EBUSY);

	log_test(logfd, "Test knet_link_set_config with link enabled");
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_link_get_status(knet_h1, 1, 0, &link_status, sizeof(struct knet_link_status)));
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, NULL, 0), EBUSY);
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 0));
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));

	log_test(logfd, "Test knet_link_set_config with static dst_addr");
	FAIL_ON_ERR(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, &lo, 0));
	host = knet_h1->host_index[1];
	link = &host->link[0];
	if (!link->access_list_match_entry_head) {
		log_test(logfd, "Unable to find default access lists for static dst_addr!");
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(knet_link_get_status(knet_h1, 1, 0, &link_status, sizeof(struct knet_link_status)));

	if ((link_status.enabled != 0) ||
	    (strcmp(link_status.src_ipaddr, "127.0.0.1")) ||
	    (strcmp(link_status.src_port, lo_portstr)) ||
	    (strcmp(link_status.dst_ipaddr, "127.0.0.1")) ||
	    (strcmp(link_status.dst_port, lo_portstr)) ||
	    (knet_h1->host_index[1]->link[0].dynamic != KNET_LINK_STATIC)) {
		log_test(logfd, "knet_link_set_config failed to set configuration.");
		log_test(logfd, "saddr: %.246s", link_status.src_ipaddr);
		log_test(logfd, "sport: %s", link_status.src_port);
		log_test(logfd, "enabled: %d, dynamic: %u",
		       link_status.enabled, knet_h1->host_index[1]->link[0].dynamic);
		TEST_EXIT_CLEAN(FAIL);
	}

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet link set config\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
