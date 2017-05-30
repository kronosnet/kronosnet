/*
 * Copyright (C) 2016 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
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
	knet_handle_t knet_h;
	int logfds[2];
	int datafd = 0;
	int8_t channel = 0;
	char recv_buff[KNET_MAX_PACKET_SIZE];
	char send_buff[KNET_MAX_PACKET_SIZE];
	ssize_t recv_len = 0;
	struct iovec iov_out[1];

	printf("Test knet_recv incorrect knet_h\n");

	if ((!knet_recv(NULL, recv_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_recv accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_new(1, logfds[1], KNET_LOG_DEBUG);

	if (!knet_h) {
		printf("knet_handle_new failed: %s\n", strerror(errno));
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	printf("Test knet_recv with no recv_buff\n");

	if ((!knet_recv(knet_h, NULL, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_recv accepted invalid recv_buff or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_recv with invalid recv_buff len (0)\n");

	if ((!knet_recv(knet_h, recv_buff, 0, channel)) || (errno != EINVAL)) {
		printf("knet_recv accepted invalid recv_buff len (0) or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_recv with invalid recv_buff len (> KNET_MAX_PACKET_SIZE)\n");

	if ((!knet_recv(knet_h, recv_buff, KNET_MAX_PACKET_SIZE + 1, channel)) || (errno != EINVAL)) {
		printf("knet_recv accepted invalid recv_buff len (> KNET_MAX_PACKET_SIZE) or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_recv with invalid channel (-1)\n");

	channel = -1;

	if ((!knet_recv(knet_h, recv_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_recv accepted invalid channel (-1) or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_recv with invalid channel (KNET_DATAFD_MAX)\n");

	channel = KNET_DATAFD_MAX;

	if ((!knet_recv(knet_h, recv_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_recv accepted invalid channel (KNET_DATAFD_MAX) or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_recv with unconfigured channel\n");

	channel = 0;

	if ((!knet_recv(knet_h, recv_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_recv accepted invalid unconfigured channel or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_recv with valid data\n");

	if (knet_handle_enable_sock_notify(knet_h, &private_data, sock_notify) < 0) {
		printf("knet_handle_enable_sock_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
        }

	datafd = 0;
	channel = -1;

	if (knet_handle_add_datafd(knet_h, &datafd, &channel) < 0) {
		printf("knet_handle_add_datafd failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	memset(recv_buff, 0, KNET_MAX_PACKET_SIZE);
	memset(send_buff, 1, sizeof(send_buff));

	iov_out[0].iov_base = (void *)send_buff;
	iov_out[0].iov_len = sizeof(send_buff);

	if (writev(knet_h->sockfd[channel].sockfd[1], iov_out, 1) != sizeof(send_buff)) {
		printf("Unable to write data: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	recv_len = knet_recv(knet_h, recv_buff, KNET_MAX_PACKET_SIZE, channel);
	if (recv_len <= 0) {
		printf("knet_recv failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (recv_len != sizeof(send_buff)) {
		printf("knet_recv received only %zd bytes: %s\n", recv_len, strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE)) {
		printf("knet_recv received bad data\n");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	need_root();

	test();

	return PASS;
}
