/*
 * Copyright (C) 2016-2022 Red Hat, Inc.  All rights reserved.
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
	int logfds[2];
	int datafd = 0;
	int8_t channel = 0;
	char recv_buff[KNET_MAX_PACKET_SIZE];
	char send_buff[KNET_MAX_PACKET_SIZE];
	ssize_t recv_len = 0;
	int res;
	struct iovec iov_out[1];

	printf("Test knet_recv incorrect knet_h\n");
	if ((!knet_recv(NULL, recv_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_recv accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h1 = knet_handle_start(logfds, KNET_LOG_DEBUG, knet_h);

	printf("Test knet_recv with no recv_buff\n");
	FAIL_ON_SUCCESS(knet_recv(knet_h1, NULL, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	printf("Test knet_recv with invalid recv_buff len (0)\n");
	FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, 0, channel), EINVAL);

	printf("Test knet_recv with invalid recv_buff len (> KNET_MAX_PACKET_SIZE)\n");
	FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE + 1, channel), EINVAL);

	printf("Test knet_recv with invalid channel (-1)\n");
	channel = -1;
	FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	printf("Test knet_recv with invalid channel (KNET_DATAFD_MAX)\n");
	channel = KNET_DATAFD_MAX;
	FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	printf("Test knet_recv with unconfigured channel\n");
	channel = 0;

	FAIL_ON_SUCCESS(knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel), EINVAL);

	printf("Test knet_recv with valid data\n");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel));

	memset(recv_buff, 0, KNET_MAX_PACKET_SIZE);
	memset(send_buff, 1, sizeof(send_buff));

	iov_out[0].iov_base = (void *)send_buff;
	iov_out[0].iov_len = sizeof(send_buff);

	if (writev(knet_h1->sockfd[channel].sockfd[1], iov_out, 1) != sizeof(send_buff)) {
		printf("Unable to write data: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	recv_len = knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel);
	if (recv_len <= 0) {
		printf("knet_recv failed: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	if (recv_len != sizeof(send_buff)) {
		printf("knet_recv received only %zd bytes: %s\n", recv_len, strerror(errno));
		CLEAN_EXIT(FAIL);
	}

	if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE)) {
		printf("knet_recv received bad data\n");
		CLEAN_EXIT(FAIL);
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}
