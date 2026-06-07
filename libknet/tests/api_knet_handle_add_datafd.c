/*
 * Copyright (C) 2016-2026 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "libknet.h"

#include "internals.h"
#include "test-common.h"

#define TEST_NAME "api_knet_handle_add_datafd"

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
	knet_handle_t knet_h[2] = {0};
	knet_handle_t knet_h1;
	int datafd = 0, i;
	int8_t channel = 0;
	int datafdmax[KNET_DATAFD_MAX];
	int8_t channels[KNET_DATAFD_MAX];
	struct sockaddr_storage lo;
	int sp[2];
	int unconnected_sock;
	int pipefd[2];
	int chardev_fd;
	int add_result;
	int saved_errno;
	int listen_sock, client_sock, server_sock;
	struct sockaddr_in addr;
	socklen_t addrlen;
	int dgram_sock1, dgram_sock2;
	struct sockaddr_in addr1, addr2;
	char send_buf[4096];
	char recv_buf[4096];
	ssize_t send_len, recv_len;

	logfd = start_logging(stdout);

	log_test(logfd, "Test knet_handle_add_datafd incorrect knet_h");

	FAIL_ON_SUCCESS(knet_handle_add_datafd(NULL, &datafd, &channel, 0), EINVAL);


	knet_h1 = _ts_knet_handle_start(logfd, KNET_LOG_DEBUG, knet_h);

	log_test(logfd, "Test knet_handle_add_datafd with no datafd");
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, NULL, &channel, 0), EINVAL);

	log_test(logfd, "Test knet_handle_add_datafd with no channel");
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, NULL, 0), EINVAL);

	log_test(logfd, "Test knet_handle_add_datafd with invalid channel");
	channel = KNET_DATAFD_MAX;

	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EINVAL);


	log_test(logfd, "Test knet_handle_add_datafd with no socknotify");
	datafd = 0;
	channel = -1;
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EINVAL);

	log_test(logfd, "Test knet_handle_add_datafd with automatic config values");
	FAIL_ON_ERR(knet_handle_enable_sock_notify(knet_h1, &private_data, sock_notify));

	datafd = 0;
	channel = -1;

	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));
	log_test(logfd, "got datafd: %d channel: %d", datafd, channel);

	log_test(logfd, "Test knet_handle_add_datafd with duplicated datafd");
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EEXIST);

	log_test(logfd, "Test knet_handle_add_datafd with busy channel");
	datafd = datafd + 1;
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EBUSY);

	datafd = datafd - 1;

	FAIL_ON_ERR(knet_handle_remove_datafd(knet_h1, datafd));

	log_test(logfd, "Test knet_handle_add_datafd with no available channels");
	for (i = 0; i < KNET_DATAFD_MAX; i++) {
		datafdmax[i] = 0;
		channels[i] = -1;
		FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafdmax[i], &channels[i], 0));
	}

	datafd = 0;
	channel = -1;

	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EBUSY);

	for (i = 0; i < KNET_DATAFD_MAX; i++) {
		FAIL_ON_ERR(knet_handle_remove_datafd(knet_h1, datafdmax[i]));
	}

	log_test(logfd, "Test knet_handle_add_datafd with user-provided AF_UNIX socketpair (should fail)");
	FAIL_ON_ERR(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp));
	datafd = sp[0];
	channel = -1;
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EINVAL);
	close(sp[0]);
	close(sp[1]);
	log_test(logfd, "Correctly rejected user-provided socketpair");

	log_test(logfd, "Test knet_handle_add_datafd with user-provided SOCK_DGRAM socketpair (should fail)");
	FAIL_ON_ERR(socketpair(AF_UNIX, SOCK_DGRAM, 0, sp));
	datafd = sp[0];
	channel = -1;
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EINVAL);
	close(sp[0]);
	close(sp[1]);
	log_test(logfd, "Correctly rejected user-provided DGRAM socketpair");

	log_test(logfd, "Test knet_handle_add_datafd with unconnected SOCK_STREAM socket (should fail)");
	FAIL_ON_ERR_ONLY(unconnected_sock = socket(AF_UNIX, SOCK_STREAM, 0));
	datafd = unconnected_sock;
	channel = -1;
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EINVAL);
	close(unconnected_sock);
	log_test(logfd, "Correctly rejected unconnected SOCK_STREAM socket");

	log_test(logfd, "Test knet_handle_add_datafd with unbound SOCK_DGRAM socket (should fail)");
	FAIL_ON_ERR_ONLY(unconnected_sock = socket(AF_UNIX, SOCK_DGRAM, 0));
	datafd = unconnected_sock;
	channel = -1;
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EINVAL);
	close(unconnected_sock);
	log_test(logfd, "Correctly rejected unbound SOCK_DGRAM socket");

	log_test(logfd, "Test knet_handle_add_datafd with pipe (should fail)");
	FAIL_ON_ERR(pipe(pipefd));
	datafd = pipefd[0];
	channel = -1;
	FAIL_ON_SUCCESS(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0), EINVAL);
	close(pipefd[0]);
	close(pipefd[1]);
	log_test(logfd, "Correctly rejected pipe (knet requires bidirectional I/O on single fd)");

	log_test(logfd, "Test knet_handle_add_datafd with character device /dev/null (validates fd type acceptance)");
	FAIL_ON_ERR_ONLY(chardev_fd = open("/dev/null", O_RDWR));
	datafd = chardev_fd;
	channel = -1;

	/* This may fail at epoll/kqueue stage (EPERM/ENODEV/EOPNOTSUPP) but should pass fd validation */
	add_result = knet_handle_add_datafd(knet_h1, &datafd, &channel, 0);
	saved_errno = errno;

	if (add_result == 0) {
		log_test(logfd, "Successfully accepted character device, datafd: %d channel: %d", datafd, channel);
		FAIL_ON_ERR(knet_handle_remove_datafd(knet_h1, datafd));
		close(chardev_fd);
	} else if (saved_errno == EPERM || saved_errno == ENODEV || saved_errno == EOPNOTSUPP) {
		log_test(logfd, "Character device passed validation but failed at epoll/kqueue (expected for non-pollable devices)");
		close(chardev_fd);
	} else {
		log_test(logfd, "*** FAIL: Unexpected error adding character device: errno=%d (%s)", saved_errno, strerror(saved_errno));
		close(chardev_fd);
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Test knet_handle_add_datafd with connected AF_INET SOCK_STREAM socket (should succeed)");
	addrlen = sizeof(addr);

	FAIL_ON_ERR_ONLY(listen_sock = socket(AF_INET, SOCK_STREAM, 0));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;  /* let kernel pick a port */
	FAIL_ON_ERR(bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)));
	FAIL_ON_ERR(listen(listen_sock, 1));
	FAIL_ON_ERR(getsockname(listen_sock, (struct sockaddr *)&addr, &addrlen));

	FAIL_ON_ERR_ONLY(client_sock = socket(AF_INET, SOCK_STREAM, 0));
	FAIL_ON_ERR(connect(client_sock, (struct sockaddr *)&addr, sizeof(addr)));
	FAIL_ON_ERR_ONLY(server_sock = accept(listen_sock, NULL, NULL));

	datafd = client_sock;
	channel = -1;
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));
	log_test(logfd, "Successfully accepted connected SOCK_STREAM socket, datafd: %d channel: %d", datafd, channel);
	FAIL_ON_ERR(knet_handle_remove_datafd(knet_h1, datafd));
	close(client_sock);
	close(server_sock);
	close(listen_sock);

	log_test(logfd, "Test knet_handle_add_datafd with connected AF_INET SOCK_DGRAM socket (should succeed)");

	FAIL_ON_ERR_ONLY(dgram_sock1 = socket(AF_INET, SOCK_DGRAM, 0));
	FAIL_ON_ERR_ONLY(dgram_sock2 = socket(AF_INET, SOCK_DGRAM, 0));

	memset(&addr1, 0, sizeof(addr1));
	addr1.sin_family = AF_INET;
	addr1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr1.sin_port = 0;
	FAIL_ON_ERR(bind(dgram_sock1, (struct sockaddr *)&addr1, sizeof(addr1)));

	memset(&addr2, 0, sizeof(addr2));
	addr2.sin_family = AF_INET;
	addr2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr2.sin_port = 0;
	FAIL_ON_ERR(bind(dgram_sock2, (struct sockaddr *)&addr2, sizeof(addr2)));

	addrlen = sizeof(addr1);
	FAIL_ON_ERR(getsockname(dgram_sock1, (struct sockaddr *)&addr1, &addrlen));
	addrlen = sizeof(addr2);
	FAIL_ON_ERR(getsockname(dgram_sock2, (struct sockaddr *)&addr2, &addrlen));

	FAIL_ON_ERR(connect(dgram_sock1, (struct sockaddr *)&addr2, sizeof(addr2)));
	FAIL_ON_ERR(connect(dgram_sock2, (struct sockaddr *)&addr1, sizeof(addr1)));

	datafd = dgram_sock1;
	channel = -1;
	FAIL_ON_ERR(knet_handle_add_datafd(knet_h1, &datafd, &channel, 0));
	log_test(logfd, "Successfully accepted connected SOCK_DGRAM socket, datafd: %d channel: %d", datafd, channel);

	FAIL_ON_ERR(knet_host_add(knet_h1, 1));
	FAIL_ON_ERR(_ts_knet_link_set_config(knet_h1, 1, 0, KNET_TRANSPORT_LOOPBACK, 0, AF_INET, 0, &lo, logfd));
	FAIL_ON_ERR(knet_link_set_enable(knet_h1, 1, 0, 1));
	FAIL_ON_ERR(knet_handle_setfwd(knet_h1, 1));
	FAIL_ON_ERR(wait_for_host(knet_h1, 1, TEST_TIMEOUT_SHORT, logfd));

	memset(send_buf, 0xBB, sizeof(send_buf));
	memset(recv_buf, 0, sizeof(recv_buf));

	send_len = knet_send(knet_h1, send_buf, sizeof(send_buf), channel);
	if (send_len <= 0) {
		log_test(logfd, "knet_send failed: %s", strerror(errno));
		close(dgram_sock1);
		close(dgram_sock2);
		TEST_EXIT_CLEAN(FAIL);
	}

	recv_len = recv(dgram_sock2, recv_buf, sizeof(recv_buf), 0);
	if (recv_len != send_len) {
		log_test(logfd, "Failed to receive knet data on dgram_sock2: got %zd, expected %zd: %s", recv_len, send_len, strerror(errno));
		close(dgram_sock1);
		close(dgram_sock2);
		TEST_EXIT_CLEAN(FAIL);
	}

	if (memcmp(send_buf, recv_buf, send_len)) {
		log_test(logfd, "Received knet data doesn't match sent data");
		close(dgram_sock1);
		close(dgram_sock2);
		TEST_EXIT_CLEAN(FAIL);
	}

	log_test(logfd, "Validated knet I/O through SOCK_DGRAM datafd");

	FAIL_ON_ERR(knet_handle_remove_datafd(knet_h1, datafd));
	close(dgram_sock1);
	close(dgram_sock2);

	TEST_EXIT_CLEAN(CONTINUE);
}

int main(int argc, char *argv[])
{
	printf("[TEST] %s: Test knet handle add datafd\n", TEST_NAME);

	test();

	TEST_EXIT(PASS);
}
