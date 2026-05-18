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
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	int datafd = 0;
	int8_t channel = 0;
	char send_buff[KNET_MAX_PACKET_SIZE];
	struct sockaddr_storage lo;

	memset(send_buff, 0, sizeof(send_buff));

	log_test(logfd, "Test knet_send_sync incorrect knet_h");

	if ((!knet_send_sync(NULL, send_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		log_test(logfd, "knet_send_sync accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		exit(FAIL);
	}


	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_send_sync with no send_buff");
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, NULL, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	log_test(logfd, "Test knet_send_sync with invalid send_buff len (0)");
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, 0, channel), EINVAL);

	log_test(logfd, "Test knet_send_sync with invalid send_buff len (> KNET_MAX_PACKET_SIZE)");
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE + 1, channel), EINVAL);

	log_test(logfd, "Test knet_send_sync with invalid channel (-1)");
	channel = -1;
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	log_test(logfd, "Test knet_send_sync with invalid channel (KNET_DATAFD_MAX)");
	channel = KNET_DATAFD_MAX;
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	log_test(logfd, "Test knet_send_sync with no filter configured");
	channel = 1;
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel), ENETDOWN);
	// coverity[LOCK:SUPPRESS] - it's a test, get over it
	// coverity[ORDER_REVERSAL:SUPPRESS] - it's a test, get over it
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, NULL, dhost_filter));


	log_test(logfd, "Test knet_send_sync with unconfigured channel");
	channel = 0;

	// coverity[ORDER_REVERSAL:SUPPRESS] - it's a test, get over it
	FAIL_ON_SUCCESS(knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	log_test(logfd, "Test knet_send_sync with data forwarding disabled");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	// coverity[ORDER_REVERSAL:SUPPRESS] - it's a test, get over it
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));

	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != ECANCELED)) {
		log_test(logfd, "knet_send_sync didn't detect datafwd disabled or returned incorrect error: %s", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_send_sync with broken dst_host_filter");
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	dhost_filter_ret = -1;
	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != EFAULT)) {
		log_test(logfd, "knet_send_sync didn't detect fatal error from dst_host_filter or returned incorrect error: %s", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_send_sync with dst_host_filter returning no host_ids_entries");
	dhost_filter_ret = 0;
	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != EINVAL)) {
		log_test(logfd, "knet_send_sync didn't detect 0 host_ids from dst_host_filter or returned incorrect error: %s", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_send_sync with host down");
	dhost_filter_ret = 1;
	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != EHOSTDOWN)) {
		log_test(logfd, "knet_send_sync didn't detect hostdown or returned incorrect error: %s", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_send_sync with dst_host_filter returning too many host_ids_entries");
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, 10, logfd, stdout));
	dhost_filter_ret = 2;
	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != E2BIG)) {
		log_test(logfd, "knet_send_sync didn't detect 2+ host_ids from dst_host_filter or returned incorrect error: %s", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	log_test(logfd, "Test knet_send_sync with dst_host_filter returning mcast packets");
	dhost_filter_ret = 3;
	if ((knet_send_sync(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != E2BIG)) {
		log_test(logfd, "knet_send_sync didn't detect mcast packet from dst_host_filter or returned incorrect error: %s", strerror(errno));
		CLEAN_EXIT(FAIL);
	}


	log_test(logfd, "Test knet_send_sync with valid data");
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
