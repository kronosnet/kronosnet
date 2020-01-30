/*
 * Copyright (C) 2016-2020 Red Hat, Inc.  All rights reserved.
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
	knet_handle_t knet_h;
	struct knet_host *host;
	struct knet_link *link;
	int logfds[2];
	char src_portstr[32];
	char dst_portstr[32];
	struct sockaddr_storage src, dst;
	struct sockaddr_in *src_in = (struct sockaddr_in *)&src;
	struct sockaddr_in *dst_in = (struct sockaddr_in *)&dst;
	struct knet_link_status link_status;

	if (make_local_sockaddr(&src, 0) < 0) {
		printf("Unable to convert src to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}
	sprintf(src_portstr, "%d", ntohs(src_in->sin_port));

	if (make_local_sockaddr(&dst, 1) < 0) {
		printf("Unable to convert dst to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}
	sprintf(dst_portstr, "%d", ntohs(dst_in->sin_port));

	printf("Test knet_link_set_config incorrect knet_h\n");

	if ((!knet_link_set_config(NULL, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0)) || (errno != EINVAL)) {
		printf("knet_link_set_config accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_link_set_config with unconfigured host_id\n");

	if ((!knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0)) || (errno != EINVAL)) {
		printf("knet_link_set_config accepted invalid host_id or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Test knet_link_set_config with bad transport type\n");

	if ((!knet_link_set_config(knet_h, 1, 0, KNET_MAX_TRANSPORTS, &src, &dst, 0)) || (errno != EINVAL)) {
		printf("knet_link_set_config accepted invalid transport or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_config with incorrect linkid\n");

	if (knet_host_add(knet_h, 1) < 0) {
		printf("Unable to add host_id 1: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((!knet_link_set_config(knet_h, 1, KNET_MAX_LINK, KNET_TRANSPORT_UDP, &src, &dst, 0)) || (errno != EINVAL)) {
		printf("knet_link_set_config accepted invalid linkid or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_config with incorrect src_addr\n");

	if ((!knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, NULL, &dst, 0)) || (errno != EINVAL)) {
		printf("knet_link_set_config accepted invalid src_addr or returned incorrect error: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_config with conflicting address families\n");

	if (make_local_sockaddr6(&dst, 1) < 0) {
		printf("Unable to convert dst to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0) == 0) {
		printf("knet_link_set_config accepted invalid address families: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_config with dynamic dst_addr\n");

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, NULL, 0) < 0) {
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
		printf("found access lists for dynamic dst_addr!\n");
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_get_status(knet_h, 1, 0, &link_status, sizeof(struct knet_link_status)) < 0) {
		printf("Unable to get link status: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((link_status.enabled != 0) ||
	    (strcmp(link_status.src_ipaddr, "127.0.0.1")) ||
	    (strcmp(link_status.src_port, src_portstr)) ||
	    (knet_h->host_index[1]->link[0].dynamic != KNET_LINK_DYNIP)) {
		printf("knet_link_set_config failed to set configuration. enabled: %d src_addr %s src_port %s dynamic %u\n",
		       link_status.enabled, link_status.src_ipaddr, link_status.src_port, knet_h->host_index[1]->link[0].dynamic);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_set_config with already configured link\n");
	if ((!knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, NULL, 0) || (errno != EBUSY))) {
		printf("knet_link_set_config accepted request while link configured or returned incorrect error: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Test knet_link_set_config with link enabled\n");

	if (knet_link_set_enable(knet_h, 1, 0, 1) < 0) {
		printf("Unable to enable link: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_get_status(knet_h, 1, 0, &link_status, sizeof(struct knet_link_status)) < 0) {
		printf("Unable to get link status: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((!knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, NULL, 0)) || (errno != EBUSY)) {
		printf("knet_link_set_config accepted request while link enabled or returned incorrect error: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_set_enable(knet_h, 1, 0, 0) < 0) {
		printf("Unable to disable link: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_clear_config(knet_h, 1, 0) < 0) {
		printf("Unable to clear link config: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Test knet_link_set_config with static dst_addr\n");

	if (make_local_sockaddr(&dst, 1) < 0) {
		printf("Unable to convert dst to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0) < 0) {
		printf("Unable to configure link: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	host = knet_h->host_index[1];
	link = &host->link[0];

	if (!knet_h->knet_transport_fd_tracker[link->outsock].access_list_match_entry_head) {
		printf("Unable to find default access lists for static dst_addr!\n");
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_get_status(knet_h, 1, 0, &link_status, sizeof(struct knet_link_status)) < 0) {
		printf("Unable to get link status: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if ((link_status.enabled != 0) ||
	    (strcmp(link_status.src_ipaddr, "127.0.0.1")) ||
	    (strcmp(link_status.src_port, src_portstr)) ||
	    (strcmp(link_status.dst_ipaddr, "127.0.0.1")) ||
	    (strcmp(link_status.dst_port, dst_portstr)) || 
	    (knet_h->host_index[1]->link[0].dynamic != KNET_LINK_STATIC)) {
		printf("knet_link_set_config failed to set configuration. enabled: %d src_addr %s src_port %s dst_addr %s dst_port %s dynamic %u\n",
		       link_status.enabled, link_status.src_ipaddr, link_status.src_port, link_status.dst_ipaddr, link_status.dst_port, knet_h->host_index[1]->link[0].dynamic);
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
