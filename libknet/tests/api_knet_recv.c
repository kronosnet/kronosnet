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
#include <sys/uio.h>

#include "libknet.h"

#include "internals.h"
#include "test-common.h"

#define TEST_NAME "api_knet_recv"

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

static void test(int datafd_flag)
{
	int logfd;
	knet_handle_t knet_h1, knet_h[2] = {0};
	int datafd = 0;
	int8_t channel = 0;
	char recv_buff[KNET_MAX_PACKET_SIZE+sizeof(struct knet_datafd_header)];
	char send_buff[KNET_MAX_PACKET_SIZE];
	ssize_t recv_len = 0;
	struct sockaddr_storage lo;

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_recv incorrect knet_h");
	FAIL_ON_SUCCESS(knet_recv(NULL, recv_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_recv with no recv_buff");
	FAIL_ON_SUCCESS(knet_recv(knet_h1, NULL, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	log_test(logfd, "Test knet_recv with invalid recv_buff len (0)");
	FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, 0, channel), EINVAL);

	log_test(logfd, "Test knet_recv with invalid channel (-1)");
	channel = -1;
	FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	log_test(logfd, "Test knet_recv with invalid channel (KNET_DATAFD_MAX)");
	channel = KNET_DATAFD_MAX;
	FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	log_test(logfd, "Test knet_recv with unconfigured channel");
	channel = 0;

	FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	log_test(logfd, "Test knet_recv with valid data");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, datafd_flag));

	if (datafd_flag == KNET_DATAFD_FLAG_RX_RETURN_INFO) {
		log_test(logfd, "Test knet_recv with invalid recv_buff len (> KNET_MAX_PACKET_SIZE + header) with RX_RETURN_INFO flag");
		FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE + sizeof(struct knet_datafd_header) + 1, channel), EINVAL);
	} else {
		log_test(logfd, "Test knet_recv with invalid recv_buff len (> KNET_MAX_PACKET_SIZE) without RX_RETURN_INFO flag");
		FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE + 1, channel), EINVAL);
	}

	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo, logfd));

	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, TEST_TIMEOUT_SHORT, logfd));

	memset(recv_buff, 0, sizeof(recv_buff));
	memset(send_buff, 1, sizeof(send_buff));

	if (knet_send(knet_h1, send_buff, sizeof(send_buff), channel) != sizeof(send_buff)) {
		log_test(logfd, "Unable to write data: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(wait_for_packet(knet_h1, TEST_TIMEOUT_SHORT, datafd, logfd));

	if (datafd_flag == KNET_DATAFD_FLAG_RX_RETURN_INFO) {
		recv_len = knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE + sizeof(struct knet_datafd_header), channel);
	} else {
		recv_len = knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel);
	}
	if (recv_len <= 0) {
		log_test(logfd, "knet_recv failed: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	if (datafd_flag == KNET_DATAFD_FLAG_RX_RETURN_INFO) {
		// Check the header
		struct knet_datafd_header *datafd_hdr = (struct knet_datafd_header *)recv_buff;

		if (datafd_hdr->size != sizeof(struct knet_datafd_header)) {
			log_test(logfd, "sizeof knet_datafd_header is wrong; got %zu, should be %zu", datafd_hdr->size, sizeof(struct knet_datafd_header));
			TEST_EXIT_CLEAN(FAIL);
		}
		if (datafd_hdr->src_nodeid != 1) {
			log_test(logfd, "knet_datafd_header has wrong nodeid; got %d, should be %d", datafd_hdr->src_nodeid, 1);
			TEST_EXIT_CLEAN(FAIL);
		}
		log_test(logfd, "got header. size = %zu, nodeid = %d", datafd_hdr->size, datafd_hdr->src_nodeid);

		if (memcmp(recv_buff+datafd_hdr->size, send_buff, sizeof(send_buff))) {
			log_test(logfd, "knet_recv received bad data");
			TEST_EXIT_CLEAN(FAIL);
		}
	} else {
		if (recv_len != sizeof(send_buff)) {
			log_test(logfd, "knet_recv received only %zd bytes: %s", recv_len, strerror(errno));
			TEST_EXIT_CLEAN(FAIL);
		}

		if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE/2)) {
			log_test(logfd, "knet_recv received bad data");
			TEST_EXIT_CLEAN(FAIL);
		}
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet recv\n", TEST_NAME);

	test(0);

	test(KNET_DATAFD_FLAG_RX_RETURN_INFO);

	TEST_EXIT(PASS);
}
