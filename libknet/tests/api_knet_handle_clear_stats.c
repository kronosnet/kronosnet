/*
 * Copyright (C) 2016-2017 Red Hat, Inc.  All rights reserved.
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

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	int datafd = 0;
	int8_t channel = 0;
	struct knet_link_status link_status;
	char send_buff[KNET_MAX_PACKET_SIZE];
	char recv_buff[KNET_MAX_PACKET_SIZE];
	ssize_t send_len = 0;
	int recv_len = 0;
	int savederrno;
	struct sockaddr_storage lo;

	if (make_local_sockaddr(&lo, 0) < 0) {
		printf("Unable to convert loopback to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	memset(send_buff, 0, sizeof(send_buff));

	printf("Test knet_handle_clear_stats incorrect knet_h\n");

	if (!knet_handle_clear_stats(NULL, 0) || (errno != EINVAL)) {
		printf("knet_handle_clear_stats accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
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

	printf("Test knet_send with valid data\n");

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

	if (knet_host_add(knet_h, 1) < 0) {
		printf("knet_host_add failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &lo, &lo, 0) < 0) {
		printf("Unable to configure link: %s\n", strerror(errno));
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_set_enable(knet_h, 1, 0, 1) < 0) {
		printf("knet_link_set_enable failed: %s\n", strerror(errno));
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_handle_setfwd(knet_h, 1) < 0) {
		printf("knet_handle_setfwd failed: %s\n", strerror(errno));
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	while(knet_h->host_index[1]->status.reachable != 1) {
		printf("waiting host to be reachable\n");
		sleep(1);
	}

	send_len = knet_send(knet_h, send_buff, KNET_MAX_PACKET_SIZE, channel);
	if (send_len <= 0) {
		printf("knet_send failed: %s\n", strerror(errno));
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (send_len != sizeof(send_buff)) {
		printf("knet_send sent only %zd bytes: %s\n", send_len, strerror(errno));
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	sleep(1);

	recv_len = knet_recv(knet_h, recv_buff, KNET_MAX_PACKET_SIZE, channel);
	savederrno = errno;
	if (recv_len != send_len) {
		printf("knet_recv received only %d bytes: %s (errno: %d)\n", recv_len, strerror(errno), errno);
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		if ((is_helgrind()) && (recv_len == -1) && (savederrno == EAGAIN)) {
			printf("helgrind exception. this is normal due to possible timeouts\n");
			exit(PASS);
		}
		exit(FAIL);
	}

	if (memcmp(recv_buff, send_buff, KNET_MAX_PACKET_SIZE)) {
		printf("recv and send buffers are different!\n");
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	/* A sanity check on the stats */
	if (knet_link_get_status(knet_h, 1, 0, &link_status, sizeof(link_status)) < 0) {
		printf("knet_link_get_status failed: %s\n", strerror(errno));
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (link_status.stats.tx_data_packets != 2 ||
	    link_status.stats.rx_data_packets != 2 ||
	    link_status.stats.tx_data_bytes < KNET_MAX_PACKET_SIZE ||
	    link_status.stats.rx_data_bytes < KNET_MAX_PACKET_SIZE ||
	    link_status.stats.tx_data_bytes > KNET_MAX_PACKET_SIZE*2 ||
	    link_status.stats.rx_data_bytes > KNET_MAX_PACKET_SIZE*2) {
	    printf("stats look wrong: tx_packets: %" PRIu64 " (%" PRIu64 " bytes), rx_packets: %" PRIu64 " (%" PRIu64 " bytes)\n",
		   link_status.stats.tx_data_packets,
		   link_status.stats.tx_data_bytes,
		   link_status.stats.rx_data_packets,
		   link_status.stats.rx_data_bytes);
	}

	printf("Test knet_clear_stats (link)\n");
	if (knet_handle_clear_stats(knet_h, KNET_CLEARSTATS_HANDLE_AND_LINK) < 0) {
		printf("knet_link_clear_stats failed: %s\n", strerror(errno));
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}


/* Check they've been cleared */
	if (knet_link_get_status(knet_h, 1, 0, &link_status, sizeof(link_status)) < 0) {
		printf("knet_link_get_status failed: %s\n", strerror(errno));
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (link_status.stats.tx_data_packets != 0 ||
	    link_status.stats.rx_data_packets != 0 ||
	    link_status.stats.tx_data_bytes != 0 ||
	    link_status.stats.rx_data_bytes != 0 ||
	    link_status.stats.tx_data_bytes != 0 ||
	    link_status.stats.rx_data_bytes != 0) {
		printf("stats not cleared: tx_packets: %" PRIu64 " (%" PRIu64 " bytes), rx_packets: %" PRIu64 " (%" PRIu64 " bytes)\n",
		       link_status.stats.tx_data_packets,
		       link_status.stats.tx_data_bytes,
		       link_status.stats.rx_data_packets,
		       link_status.stats.rx_data_bytes);

		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	knet_link_set_enable(knet_h, 1, 0, 0);
	knet_link_clear_config(knet_h, 1, 0);
	knet_host_remove(knet_h, 1);
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
