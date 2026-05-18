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
#include <inttypes.h>

#include "libknet.h"

#include "internals.h"
#include "netutils.h"
#include "test-common.h"

#define TEST_NAME "api_knet_handle_clear_stats"

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
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	int datafd = 0;
	int8_t channel = 0;
	struct knet_link_status link_status;
	char send_buff[KNET_MAX_PACKET_SIZE];
	char recv_buff[KNET_MAX_PACKET_SIZE];
	ssize_t send_len = 0;
	int recv_len = 0;
	int savederrno;
	struct sockaddr_storage lo;

	memset(send_buff, 0, sizeof(send_buff));

	log_test(logfd, "Test knet_handle_clear_stats incorrect knet_h");

	if (!knet_handle_clear_stats(NULL, 0) || (errno != EINVAL)) {
		log_test(logfd, "knet_handle_clear_stats accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_send with valid data");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel));

	FAIL_ON_ERR(knet_host_add(knet_h1, 1));

	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));

	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));

	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));

	FAIL_ON_ERR(wait_for_host(knet_h1, 1, TEST_TIMEOUT_SHORT, logfd));

	send_len = knet_send(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel);
	if (send_len <= 0) {
		log_test(logfd, "knet_send failed: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	if (send_len != sizeof(send_buff)) {
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(wait_for_packet(knet_h1, TEST_TIMEOUT_SHORT, datafd, logfd));

	recv_len = knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel);
	savederrno = errno;
	if (recv_len != send_len) {
		log_test(logfd, "knet_recv received only %d bytes: %s (errno: %d)", recv_len, strerror(errno), errno);

		if ((is_helgrind()) && (recv_len == -1) && (savederrno == EAGAIN)) {
			log_test(logfd, "helgrind exception. this is normal due to possible timeouts");
			TEST_EXIT_CLEAN(PASS);
		}
		TEST_EXIT_CLEAN(FAIL);
	}

	if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE)) {
		log_test(logfd, "recv and send buffers are different!");
		TEST_EXIT_CLEAN(FAIL);
	}

	/* A sanity check on the stats */
	FAIL_ON_ERR(knet_link_get_status(knet_h1, 1, 0, &link_status, sizeof(link_status)));

	if (link_status.stats.tx_data_packets != 2 ||
	    link_status.stats.rx_data_packets != 2 ||
	    link_status.stats.tx_data_bytes < KNET_MAX_PACKET_SIZE ||
	    link_status.stats.rx_data_bytes < KNET_MAX_PACKET_SIZE ||
	    link_status.stats.tx_data_bytes > KNET_MAX_PACKET_SIZE*2 ||
	    link_status.stats.rx_data_bytes > KNET_MAX_PACKET_SIZE*2) {
	    log_test(logfd, "stats look wrong: tx_packets: %" PRIu64 " (%" PRIu64 " bytes), rx_packets: %" PRIu64 " (%" PRIu64 " bytes)",
		   link_status.stats.tx_data_packets,
		   link_status.stats.tx_data_bytes,
		   link_status.stats.rx_data_packets,
		   link_status.stats.rx_data_bytes);
	}

	log_test(logfd, "Test knet_clear_stats (link)");
	FAIL_ON_ERR(knet_handle_clear_stats(knet_h1, KNET_CLEARSTATS_HANDLE_AND_LINK));

/* Check they've been cleared */
	FAIL_ON_ERR(knet_link_get_status(knet_h1, 1, 0, &link_status, sizeof(link_status)));

	if (link_status.stats.tx_data_packets != 0 ||
	    link_status.stats.rx_data_packets != 0 ||
	    link_status.stats.tx_data_bytes != 0 ||
	    link_status.stats.rx_data_bytes != 0 ||
	    link_status.stats.tx_data_bytes != 0 ||
	    link_status.stats.rx_data_bytes != 0) {
		log_test(logfd, "stats not cleared: tx_packets: %" PRIu64 " (%" PRIu64 " bytes), rx_packets: %" PRIu64 " (%" PRIu64 " bytes)",
		       link_status.stats.tx_data_packets,
		       link_status.stats.tx_data_bytes,
		       link_status.stats.rx_data_packets,
		       link_status.stats.rx_data_bytes);

		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle clear stats\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
