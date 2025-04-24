/*
 * Copyright (C) 2016-2025 Red Hat, Inc.  All rights reserved.
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

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	struct knet_host *host;
	struct knet_link *link;
	int logfds[2];
	char lo_portstr[32];
	struct sockaddr_storage lo, lo6;
	struct sockaddr_in *lo_in = (struct sockaddr_in *)&lo;
	struct knet_link_status link_status;

	if (make_local_sockaddr(&lo, -1) < 0) {
		printf("Unable to convert src to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}
	sprintf(lo_portstr, "%d", ntohs(lo_in->sin_port));

	printf("Test knet_link_set_config incorrect knet_h\n");

	if ((!knet_link_set_config(NULL, 1, 0, KNET_TRANSPORT_UDP, &lo, &lo, 0)) || (errno != EINVAL)) {
		printf("knet_link_set_config accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);
	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_link_set_config with unconfigured host_id\n");
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, &lo, 0), EINVAL);

	printf("Test knet_link_set_config with bad transport type\n");
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_MAX_TRANSPORTS, &lo, &lo, 0), EINVAL);

	printf("Test knet_link_set_config with incorrect linkid\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, KNET_MAX_LINK, KNET_TRANSPORT_UDP, &lo, &lo, 0), EINVAL);

	printf("Test knet_link_set_config with incorrect src_addr\n");
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, NULL, &lo, 0), EINVAL);

	printf("Test knet_link_set_config with conflicting address families\n");
	FAIL_ON_ERR(make_local_sockaddr6(&lo6, -1));
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, &lo6, 0), EINVAL);

	printf("Test knet_link_set_config with dynamic dst_addr\n");
	FAIL_ON_ERR(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, NULL, 0));
	host = knet_h1->host_index[1];
	link = &host->link[0];
	if (link->access_list_match_entry_head) {
		printf("found access lists for dynamic dst_addr!\n");
		CLEAN_EXIT(FAIL);
	}

	FAIL_ON_ERR(knet_link_get_status(knet_h1, 1, 0, &link_status, sizeof(struct knet_link_status)));

	if ((link_status.enabled != 0) ||
	    (strcmp(link_status.src_ipaddr, "127.0.0.1")) ||
	    (strcmp(link_status.src_port, lo_portstr)) ||
	    (knet_h1->host_index[1]->link[0].dynamic != KNET_LINK_DYNIP)) {
		printf("knet_link_set_config failed to set configuration. enabled: %d src_addr %s src_port %s dynamic %u\n",
		       link_status.enabled, link_status.src_ipaddr, link_status.src_port, knet_h1->host_index[1]->link[0].dynamic);
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_link_set_config with dynamic link (0) and static link (1)\n");
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 1, KNET_TRANSPORT_UDP, &lo, &lo, 0), EINVAL);

	printf("Test knet_link_set_config with already configured link\n");
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, NULL, 0), EBUSY);

	printf("Test knet_link_set_config with link enabled\n");
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_link_get_status(knet_h1, 1, 0, &link_status, sizeof(struct knet_link_status)));
	FAIL_ON_SUCCESS(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, NULL, 0), EBUSY);
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 0));
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));

	printf("Test knet_link_set_config with static dst_addr\n");
	FAIL_ON_ERR(knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, &lo, &lo, 0));
	host = knet_h1->host_index[1];
	link = &host->link[0];
	if (!link->access_list_match_entry_head) {
		printf("Unable to find default access lists for static dst_addr!\n");
		CLEAN_EXIT(FAIL);
	}

	FAIL_ON_ERR(knet_link_get_status(knet_h1, 1, 0, &link_status, sizeof(struct knet_link_status)));

	if ((link_status.enabled != 0) ||
	    (strcmp(link_status.src_ipaddr, "127.0.0.1")) ||
	    (strcmp(link_status.src_port, lo_portstr)) ||
	    (strcmp(link_status.dst_ipaddr, "127.0.0.1")) ||
	    (strcmp(link_status.dst_port, lo_portstr)) ||
	    (knet_h1->host_index[1]->link[0].dynamic != KNET_LINK_STATIC)) {
		printf("knet_link_set_config failed to set configuration. enabled: %d src_addr %s src_port %s dst_addr %s dst_port %s dynamic %u\n",
		       link_status.enabled, link_status.src_ipaddr, link_status.src_port, link_status.dst_ipaddr, link_status.dst_port, knet_h1->host_index[1]->link[0].dynamic);
		CLEAN_EXIT(FAIL);
	}

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
