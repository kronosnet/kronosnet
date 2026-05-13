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

#define TEST_NAME "api_knet_send_loopback"

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
	dst_host_ids[0] = 1;
	*dst_host_ids_entries = 1;

	return 0;
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


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);


	log_test(logfd, "Test configuring multiple links with loopback");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo, logfd));

	if (_ts_knet_link_set_config(knet_h1, 1, 1, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo, logfd) == 0) {
		log_test(logfd, "Managed to configure two LOOPBACK links - this is wrong");
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test configuring UDP link after loopback");

	if (_ts_knet_link_set_config(knet_h1, 1, 1, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd) == 0) {
		log_test(logfd, "Managed to configure UDP and LOOPBACK links together: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test configuring UDP link before loopback");
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo, logfd));
	if (_ts_knet_link_set_config(knet_h1, 1, 1, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo, logfd) == 0) {
		log_test(logfd, "Managed to configure LOOPBACK link after UDP: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}
	log_test(logfd, "Test knet_send with valid data");

	FAIL_ON_ERR(knet_handle_enable_access_lists(knet_h1, 1));
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, 10, logfd, stdout));

	send_len = knet_send(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel);
	if (send_len <= 0) {
		log_test(logfd, "knet_send failed: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	if (send_len != sizeof(send_buff)) {
		log_test(logfd, "knet_send sent only %zd bytes: %s", send_len, strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 0));

	FAIL_ON_ERR(wait_for_packet(knet_h1, 10, datafd, logfd, stdout));

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

	if (link_status.stats.tx_data_packets != 1 ||
	    link_status.stats.rx_data_packets != 0 ||
	    link_status.stats.tx_data_bytes != KNET_MAX_PACKET_SIZE) {
	    log_test(logfd, "stats look wrong: tx_packets: %" PRIu64 " (%" PRIu64 " bytes), rx_packets: %" PRIu64 " (%" PRIu64 " bytes)",
		   link_status.stats.tx_data_packets,
		   link_status.stats.tx_data_bytes,
		   link_status.stats.rx_data_packets,
		   link_status.stats.rx_data_bytes);
	}

	log_test(logfd, "Test knet_send with only localhost");
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, NULL, dhost_filter));

	send_len = knet_send(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel);
	if (send_len <= 0) {
		log_test(logfd, "knet_send failed: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	if (send_len != sizeof(send_buff)) {
		log_test(logfd, "knet_send sent only %zd bytes: %s", send_len, strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 0));
	FAIL_ON_ERR(wait_for_packet(knet_h1, 10, datafd, logfd, stdout));

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

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet send loopback\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
