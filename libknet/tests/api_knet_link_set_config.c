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
#include "link.h"
#include "netutils.h"
#include "test-common.h"

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	struct sockaddr_storage src, dst;
	struct knet_link_status link_status;

	memset(&src, 0, sizeof(struct sockaddr_storage));

	if (knet_strtoaddr("127.0.0.1", "50000", &src, sizeof(struct sockaddr_storage)) < 0) {
		printf("Unable to convert src to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	memset(&dst, 0, sizeof(struct sockaddr_storage));

	if (knet_strtoaddr("127.0.0.1", "50001", &dst, sizeof(struct sockaddr_storage)) < 0) {
		printf("Unable to convert dst to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	printf("Test knet_link_set_config incorrect knet_h\n");

	if ((!knet_link_set_config(NULL, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0)) || (errno != EINVAL)) {
		printf("knet_link_set_config accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
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

	printf("Test knet_link_set_config with unconfigured host_id\n");

	if ((!knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0)) || (errno != EINVAL)) {
		printf("knet_link_set_config accepted invalid host_id or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Test knet_link_set_config with bad transport type\n");

	if ((!knet_link_set_config(knet_h, 1, 0, KNET_MAX_TRANSPORTS+1, &src, &dst, 0)) || (errno != EINVAL)) {
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

	printf("Test knet_link_set_config with dynamic dst_addr\n");

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, NULL, 0) < 0) {
		printf("Unable to configure link: %s\n", strerror(errno));
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
	    (strcmp(link_status.src_port, "50000")) ||
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

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &src, &dst, 0) < 0) {
		printf("Unable to configure link: %s\n", strerror(errno));
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
	    (strcmp(link_status.src_port, "50000")) ||
	    (strcmp(link_status.dst_ipaddr, "127.0.0.1")) ||
	    (strcmp(link_status.dst_port, "50001")) || 
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
	need_root();

	test();

	return PASS;
}
