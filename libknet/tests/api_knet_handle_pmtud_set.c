/*
 * Copyright (C) 2016-2024 Red Hat, Inc.  All rights reserved.
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
#include "test-common.h"

static int private_data;

static void sock_notify(void *pvt_data,
			int datafd,
			int8_t channel,
			uint8_t tx_rx,
			int error,
			int errorno)
{
	return;
}

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int res;
	int logfds[2];
	unsigned int iface_mtu = 0, data_mtu;
	int datafd = 0;
	int8_t channel = 0;
	struct sockaddr_storage lo;

	printf("Test knet_handle_pmtud_set incorrect knet_h\n");

	if ((!knet_handle_pmtud_set(NULL, iface_mtu)) || (errno != EINVAL)) {
		printf("knet_handle_pmtud_set accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	flush_logs(logfds[0], stdout);

	iface_mtu = KNET_PMTUD_SIZE_V4 + 1;

	printf("Test knet_handle_pmtud_set with wrong iface_mtu\n");
	FAIL_ON_SUCCESS(knet_handle_pmtud_set(knet_h1, iface_mtu), EINVAL);
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel));

	FAIL_ON_ERR(knet_host_add(knet_h1, 1));

	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo));

	FAIL_ON_ERR(knet_link_set_pong_count(knet_h1, 1, 0, 1));

	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));

	FAIL_ON_ERR(wait_for_host(knet_h1, 1, 4, logfds[0], stdout));

	FAIL_ON_ERR(knet_handle_pmtud_get(knet_h1, &data_mtu));

	/*
	 * 28 = IP (20) + UDP (8)
	 */
	iface_mtu = data_mtu + 28 + KNET_HEADER_ALL_SIZE - 64;
	printf("Test knet_handle_pmtud_set with iface_mtu %u\n", iface_mtu);

	FAIL_ON_ERR(knet_handle_pmtud_set(knet_h1, iface_mtu));

	/*
	 * wait for PMTUd to pick up the change
	 */
	test_sleep(knet_h1, 1);
	flush_logs(logfds[0], stdout);

	if (knet_h1->data_mtu != data_mtu - 64) {
		printf("knet_handle_pmtud_set failed to set the value\n");
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_handle_pmtud_set with iface_mtu 0\n");
	FAIL_ON_ERR(knet_handle_pmtud_set(knet_h1, 0));

	/*
	 * wait for PMTUd to pick up the change
	 */
	test_sleep(knet_h1, 1);
	flush_logs(logfds[0], stdout);

	if (knet_h1->data_mtu != data_mtu) {
		printf("knet_handle_pmtud_set failed to redetect MTU: detected mtu: %u data_mtu: %u \n", knet_h1->data_mtu, data_mtu);
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
