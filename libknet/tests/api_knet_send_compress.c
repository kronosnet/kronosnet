/*
 * Copyright (C) 2016-2023 Red Hat, Inc.  All rights reserved.
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

#include "compress.h"
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

static void test(const char *model)
{
	knet_handle_t knet_h1, knet_h[2];
	int logfds[2];
	int datafd = 0;
	int8_t channel = 0;
	struct knet_handle_stats stats;
	char send_buff[KNET_MAX_PACKET_SIZE];
	char recv_buff[KNET_MAX_PACKET_SIZE];
	ssize_t send_len = 0;
	int recv_len = 0;
	int savederrno;
	int res;
	struct sockaddr_storage lo;
	struct knet_handle_compress_cfg knet_handle_compress_cfg;

	memset(send_buff, 0, sizeof(send_buff));

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	flush_logs(logfds[0], stdout);

	printf("Test knet_send with %s and valid data\n", model);

	memset(&knet_handle_compress_cfg, 0, sizeof(struct knet_handle_compress_cfg));
	strncpy(knet_handle_compress_cfg.compress_model, model, sizeof(knet_handle_compress_cfg.compress_model) - 1);
	knet_handle_compress_cfg.compress_level = 4;
	knet_handle_compress_cfg.compress_threshold = 0;

	FAIL_ON_ERR(knet_handle_compress(knet_h1, &knet_handle_compress_cfg));

	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel));

	FAIL_ON_ERR(knet_host_add(knet_h1, 1));

	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_UDP, 0, AF_INET, 0, &lo));

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

	/* A sanity check on the stats */
	FAIL_ON_ERR(knet_handle_get_stats(knet_h1, &stats, sizeof(stats)));

	if (strcmp(model, "none") == 0) {
		if (stats.tx_compressed_packets != 0 ||
		    stats.rx_compressed_packets != 0) {

			printf("stats look wrong: s/b all 0 for model 'none' tx_packets: %" PRIu64 " (%" PRIu64 "/%" PRIu64 " comp/uncomp), rx_packets: %" PRIu64 " (%" PRIu64 "/%" PRIu64 " comp/uncomp)\n",
			       stats.tx_compressed_packets,
			       stats.tx_compressed_size_bytes,
			       stats.tx_compressed_original_bytes,
			       stats.rx_compressed_packets,
			       stats.rx_compressed_size_bytes,
			       stats.rx_compressed_original_bytes);
		}
	} else {
		if (stats.tx_compressed_packets != 1 ||
		    stats.rx_compressed_packets != 1 ||
		    stats.tx_compressed_original_bytes < stats.tx_compressed_size_bytes ||
		    stats.tx_compressed_original_bytes < stats.tx_compressed_size_bytes) {
			printf("stats look wrong: tx_packets: %" PRIu64 " (%" PRIu64 "/%" PRIu64 " comp/uncomp), rx_packets: %" PRIu64 " (%" PRIu64 "/%" PRIu64 " comp/uncomp)\n",
			       stats.tx_compressed_packets,
			       stats.tx_compressed_size_bytes,
			       stats.tx_compressed_original_bytes,
			       stats.rx_compressed_packets,
			       stats.rx_compressed_size_bytes,
			       stats.rx_compressed_original_bytes);

		}
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	struct knet_compress_info compress_list[16];
	size_t compress_list_entries;
	size_t i;

	memset(compress_list, 0, sizeof(compress_list));

	if (knet_get_compress_list(compress_list, &compress_list_entries) < 0) {
		printf("knet_get_compress_list failed: %s\n", strerror(errno));
		return FAIL;
	}

	if (compress_list_entries == 0) {
		printf("no compression modules detected. Skipping\n");
		return SKIP;
	}

	test("none");

	for (i=0; i < compress_list_entries; i++) {
		test(compress_list[i].name);
	}

	return PASS;
}
