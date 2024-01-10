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
#include "netutils.h"
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

static int dhost_filter_ret = 0;

static int dhost_filter(void *pvt_data,
			const unsigned char *outdata,
			ssize_t outdata_len,
			uint8_t tx_rx,
			knet_node_id_t this_host_id,
			knet_node_id_t src_host_id,
			int8_t *dst_channel,
			knet_node_id_t *dst_host_ids,
			size_t *dst_host_ids_entries)
{
	dst_host_ids[0] = 0;

	/*
	 * fatal fault
	 */
	if (dhost_filter_ret < 0) {
		return -1;
	}

	/*
	 * trigger EINVAL
	 * no ids found
	 */
	if (dhost_filter_ret == 0) {
		*dst_host_ids_entries = 0;
		return 0;
	}

	/*
 	 * send correct info back
 	 */

	if (dhost_filter_ret == 1) {
		dst_host_ids[0] = 1;
		*dst_host_ids_entries = 1;
		return 0;
	}

	/*
	 * trigger E2BIG
	 * mcast destinations
	 */
	if (dhost_filter_ret == 2) {
		dst_host_ids[0] = 1;
		*dst_host_ids_entries = 2;
		return 0;
	}

	/*
	 * return mcast
	 */
	if (dhost_filter_ret == 3) {
		return 1;
	}

	return dhost_filter_ret;
}

static void test(void)
{
	knet_handle_t knet_h1, knet_h[2];
	int logfds[2];
	int datafd = 0;
	int8_t channel = 0;
	char send_buff[KNET_MAX_PACKET_SIZE];
	struct sockaddr_storage lo;
	int res;

	memset(send_buff, 0, sizeof(send_buff));

	printf("Test knet_send_sync incorrect knet_h\n");

	if ((!knet_send_sync(NULL, send_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_send_sync accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_send_sync with no send_buff\n");
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, NULL, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	printf("Test knet_send_sync with invalid send_buff len (0)\n");
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, 0, channel), EINVAL);

	printf("Test knet_send_sync with invalid send_buff len (> KNET_MAX_PACKET_SIZE)\n");
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE + 1, channel), EINVAL);

	printf("Test knet_send_sync with invalid channel (-1)\n");
	channel = -1;
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	printf("Test knet_send_sync with invalid channel (KNET_DATAFD_MAX)\n");
	channel = KNET_DATAFD_MAX;
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	printf("Test knet_send_sync with no filter configured\n");
	channel = 1;
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel), ENETDOWN);
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, NULL, dhost_filter));


	printf("Test knet_send_sync with unconfigured channel\n");
	channel = 0;
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	printf("Test knet_send_sync with data forwarding disabled\n");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel));

	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != ECANCELED)) {
		printf("knet_send_sync didn't detect datafwd disabled or returned incorrect error: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_send_sync with broken dst_host_filter\n");
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	dhost_filter_ret = -1;
	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != EFAULT)) {
		printf("knet_send_sync didn't detect fatal error from dst_host_filter or returned incorrect error: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_send_sync with dst_host_filter returning no host_ids_entries\n");
	dhost_filter_ret = 0;
	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != EINVAL)) {
		printf("knet_send_sync didn't detect 0 host_ids from dst_host_filter or returned incorrect error: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_send_sync with host down\n");
	dhost_filter_ret = 1;
	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != EHOSTDOWN)) {
		printf("knet_send_sync didn't detect hostdown or returned incorrect error: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_send_sync with dst_host_filter returning too many host_ids_entries\n");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo));
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, 10, logfds[0], stdout));
	dhost_filter_ret = 2;
	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != E2BIG)) {
		printf("knet_send_sync didn't detect 2+ host_ids from dst_host_filter or returned incorrect error: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	printf("Test knet_send_sync with dst_host_filter returning mcast packets\n");
	dhost_filter_ret = 3;
	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != E2BIG)) {
		printf("knet_send_sync didn't detect mcast packet from dst_host_filter or returned incorrect error: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}


	printf("Test knet_send_sync with valid data\n");
	dhost_filter_ret = 1;
	FAIL_ON_ERR(knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel));

	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 0));

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
