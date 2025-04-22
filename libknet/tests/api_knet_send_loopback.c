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
#include <inttypes.h>

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
	knet_handle_t knet_h1, knet_h[2];
	int logfds[2];
	int datafd = 0;
	int8_t channel = 0;
	struct knet_link_status link_status;
	char send_buff[KNET_MAX_PACKET_SIZE];
	char recv_buff[KNET_MAX_PACKET_SIZE];
	ssize_t send_len = 0;
	int recv_len = 0;
	int savederrno;
	int res;
	struct sockaddr_storage lo;

	memset(send_buff, 0, sizeof(send_buff));

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	flush_logs(logfds[0], stdout);

	printf("Test configuring multiple links with loopback\n");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));
	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo));

	if (_knet_link_set_config(knet_h1, 1, 1, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo) == 0) {
		printf("Managed to configure two LOOPBACK links - this is wrong\n");
		CLEAN_EXIT(FAIL);
	}

	printf("Test configuring UDP link after loopback\n");

	if (_knet_link_set_config(knet_h1, 1, 1, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo) == 0) {
		printf("Managed to configure UDP and LOOPBACK links together: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	printf("Test configuring UDP link before loopback\n");
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo));
	if (_knet_link_set_config(knet_h1, 1, 1, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo) == 0) {
		printf("Managed to configure LOOPBACK link after UDP: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}
	printf("Test knet_send with valid data\n");

	FAIL_ON_ERR(knet_handle_enable_access_lists(knet_h1, 1));
	FAIL_ON_ERR(knet_link_clear_config(knet_h1, 1, 0));
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo));
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, 10, logfds[0], stdout));

	send_len = knet_send(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel);
	if (send_len <= 0) {
		printf("knet_send failed: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	if (send_len != sizeof(send_buff)) {
		printf("knet_send sent only %zd bytes: %s\n", send_len, strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 0));

	FAIL_ON_ERR(wait_for_packet(knet_h1, 10, datafd, logfds[0], stdout))

	recv_len = knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel);
	savederrno = errno;
	if (recv_len != send_len) {
		printf("knet_recv received only %d bytes: %s (errno: %d)\n", recv_len, strerror(errno), errno);
		if ((is_helgrind()) && (recv_len == -1) && (savederrno == EAGAIN)) {
			printf("helgrind exception. this is normal due to possible timeouts\n");
			CLEAN_EXIT(PASS);
		}
		CLEAN_EXIT(FAIL);
	}

	if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE)) {
		printf("recv and send buffers are different!\n");
		CLEAN_EXIT(FAIL);
	}

	/* A sanity check on the stats */
	FAIL_ON_ERR(knet_link_get_status(knet_h1, 1, 0, &link_status, sizeof(link_status)));

	if (link_status.stats.tx_data_packets != 1 ||
	    link_status.stats.rx_data_packets != 0 ||
	    link_status.stats.tx_data_bytes != KNET_MAX_PACKET_SIZE) {
	    printf("stats look wrong: tx_packets: %" PRIu64 " (%" PRIu64 " bytes), rx_packets: %" PRIu64 " (%" PRIu64 " bytes)\n",
		   link_status.stats.tx_data_packets,
		   link_status.stats.tx_data_bytes,
		   link_status.stats.rx_data_packets,
		   link_status.stats.rx_data_bytes);
	}

	printf("Test knet_send with only localhost\n");
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(knet_handle_enable_filter(knet_h1, NULL, dhost_filter));

	send_len = knet_send(knet_h1, send_buff, KNET_MAX_PACKET_SIZE, channel);
	if (send_len <= 0) {
		printf("knet_send failed: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	if (send_len != sizeof(send_buff)) {
		printf("knet_send sent only %zd bytes: %s\n", send_len, strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 0));
	FAIL_ON_ERR(wait_for_packet(knet_h1, 10, datafd, logfds[0], stdout));

	recv_len = knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel);
	savederrno = errno;
	if (recv_len != send_len) {
		printf("knet_recv received only %d bytes: %s (errno: %d)\n", recv_len, strerror(errno), errno);
		if ((is_helgrind()) && (recv_len == -1) && (savederrno == EAGAIN)) {
			printf("helgrind exception. this is normal due to possible timeouts\n");
			CLEAN_EXIT(PASS);
		}
		CLEAN_EXIT(FAIL);
	}

	if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE)) {
		printf("recv and send buffers are different!\n");
		CLEAN_EXIT(FAIL);
	}

	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
