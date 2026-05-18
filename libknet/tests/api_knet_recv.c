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

static void test(void)
{
	int logfd;

	logfd = start_logging(stdout);
	knet_handle_t knet_h1, knet_h[2];
	int datafd = 0;
	int8_t channel = 0;
	char recv_buff[KNET_MAX_PACKET_SIZE];
	char send_buff[KNET_MAX_PACKET_SIZE];
	ssize_t recv_len = 0;
	struct sockaddr_storage lo;

	log_test(logfd, "Test knet_recv incorrect knet_h");
	if ((!knet_recv(NULL, recv_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		log_test(logfd, "knet_recv accepted invalid knet_h or returned incorrect error: %s", strerror(errno));
		TEST_EXIT(FAIL);
	}


	knet_h1 = knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_recv with no recv_buff");
	FAIL_ON_SUCCESS(knet_recv(knet_h1, NULL, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	log_test(logfd, "Test knet_recv with invalid recv_buff len (0)");
	FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, 0, channel), EINVAL);

	log_test(logfd, "Test knet_recv with invalid recv_buff len (> KNET_MAX_PACKET_SIZE)");
	FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE + 1, channel), EINVAL);

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

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel));

	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo, logfd));

	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, 10, logfd, stdout));

	memset(recv_buff, 0, KNET_MAX_PACKET_SIZE);
	memset(send_buff, 1, sizeof(send_buff));

//	if (writev(knet_h1->sockfd[channel].sockfd[1], iov_out, 1) != sizeof(send_buff)) {
	if (knet_send(knet_h1, send_buff, sizeof(send_buff), channel) != sizeof(send_buff)) {
		log_test(logfd, "Unable to write data: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	FAIL_ON_ERR(wait_for_packet(knet_h1, TEST_TIMEOUT_SHORT, datafd, logfd));

	recv_len = knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel);
	if (recv_len <= 0) {
		log_test(logfd, "knet_recv failed: %s", strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	if (recv_len != sizeof(send_buff)) {
		log_test(logfd, "knet_recv received only %zd bytes: %s", recv_len, strerror(errno));
		TEST_EXIT_CLEAN(FAIL);
	}

	if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE)) {
		log_test(logfd, "knet_recv received bad data");
		TEST_EXIT_CLEAN(FAIL);
	}
	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet recv\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
