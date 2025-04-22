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

static void test(int datafd_flag)
{
	knet_handle_t knet_h1, knet_h[2];
	int logfds[2];
	int datafd = 0;
	int8_t channel = 0;
	char recv_buff[KNET_MAX_PACKET_SIZE];
	char send_buff[KNET_MAX_PACKET_SIZE-sizeof(struct knet_datafd_header)];
	ssize_t recv_len = 0;
	int retry_cnt = 0;
	struct sockaddr_storage lo;
	int res;

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

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, datafd_flag));

	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo));

	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, 10, logfds[0], stdout));

	memset(recv_buff, 0, KNET_MAX_PACKET_SIZE);
	memset(send_buff, 1, sizeof(send_buff));

//	if (writev(knet_h1->sockfd[channel].sockfd[1], iov_out, 1) != sizeof(send_buff)) {
	if (knet_send(knet_h1, send_buff, sizeof(send_buff), channel) != sizeof(send_buff)) {
		printf("Unable to write data: %s\n", strerror(errno));
		CLEAN_EXIT(FAIL);
	}

retry:
	recv_len = knet_recv(knet_h1, recv_buff, KNET_MAX_PACKET_SIZE, channel);
	if (recv_len <= 0) {
		printf("knet_recv failed: %s\n", strerror(errno));
		if (errno == EAGAIN && ++retry_cnt < 3) {
			sleep(1);
			goto retry;
		}
		CLEAN_EXIT(FAIL);
	}

	if (datafd_flag == KNET_DATAFD_FLAG_RX_RETURN_INFO) {
		// Check the header
		struct knet_datafd_header *datafd_hdr = (struct knet_datafd_header *)recv_buff;

		if (datafd_hdr->size != sizeof(struct knet_datafd_header)) {
			printf("sizeof knet_datafd_header is wrong; got %zu, should be %zu\n", datafd_hdr->size, sizeof(struct knet_datafd_header));
			CLEAN_EXIT(FAIL);
		}
		if (datafd_hdr->src_nodeid != 1) {
			printf("knet_datafd_header has wrong nodeid; got %d, should be %d\n", datafd_hdr->src_nodeid, 1);
			CLEAN_EXIT(FAIL);
		}
		printf("got header. size = %zu, nodeid = %d\n", datafd_hdr->size, datafd_hdr->src_nodeid);

		if (memcmp(recv_buff+datafd_hdr->size, send_buff, sizeof(send_buff))) {
			printf("knet_recv received bad data\n");
			CLEAN_EXIT(FAIL);
		}
	} else {
		if (recv_len != sizeof(send_buff)) {
			printf("knet_recv received only %zd bytes: %s\n", recv_len, strerror(errno));
			CLEAN_EXIT(FAIL);
		}

		if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE/2)) {
			printf("knet_recv received bad data\n");
			CLEAN_EXIT(FAIL);
		}
	}
	CLEAN_EXIT(CONTINUE);
}

int main(int argc, char *argv[])
{
	test(0);

	test(KNET_DATAFD_FLAG_RX_RETURN_INFO);

	return PASS;
}
