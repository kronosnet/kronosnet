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

static int dhost_filter_ret = 0;

static int dhost_filter(void *pvt_data,
			const unsigned char *outdata,
			ssize_t outdata_len,
			uint8_t tx_rx,
			uint16_t this_host_id,
			uint16_t src_host_id,
			int8_t *dst_channel,
			uint16_t *dst_host_ids,
			size_t *dst_host_ids_entries)
{
	dst_host_ids[0] = 0;

	/*
	 * fatal fault
	 */
	if (dhost_filter_ret < 0) {
		return -1;
	}

	/*
	 * trigger EINVAL
	 * no ids found
	 */
	if (dhost_filter_ret == 0) {
		*dst_host_ids_entries = 0;
		return 0;
	}

	/*
 	 * send correct info back
 	 */

	if (dhost_filter_ret == 1) {
		dst_host_ids[0] = 1;
		*dst_host_ids_entries = 1;
		return 0;
	}

	/*
	 * trigger E2BIG
	 * mcast destinations
	 */
	if (dhost_filter_ret == 2) {
		dst_host_ids[0] = 1;
		*dst_host_ids_entries = 2;
		return 0;
	}

	/*
	 * return mcast
	 */
	if (dhost_filter_ret == 3) {
		return 1;
	}

	return dhost_filter_ret;
}

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];
	int datafd = 0;
	int8_t channel = 0;
	char send_buff[KNET_MAX_PACKET_SIZE];
	struct sockaddr_storage lo;

	memset(&lo, 0, sizeof(struct sockaddr_storage));

	if (strtoaddr("127.0.0.1", "50000", (struct sockaddr *)&lo, sizeof(struct sockaddr_storage)) < 0) {
		printf("Unable to convert loopback to sockaddr: %s\n", strerror(errno));
		exit(FAIL);
	}

	memset(send_buff, 0, sizeof(send_buff));

	printf("Test knet_send_sync incorrect knet_h\n");

	if ((!knet_send_sync(NULL, send_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_send_sync accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
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

	printf("Test knet_send_sync with no send_buff\n");

	if ((!knet_send_sync(knet_h, NULL, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_send_sync accepted invalid send_buff or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with invalid send_buff len (0)\n");

	if ((!knet_send_sync(knet_h, send_buff, 0, channel)) || (errno != EINVAL)) {
		printf("knet_send_sync accepted invalid send_buff len (0) or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with invalid send_buff len (> KNET_MAX_PACKET_SIZE)\n");

	if ((!knet_send_sync(knet_h, send_buff, KNET_MAX_PACKET_SIZE + 1, channel)) || (errno != EINVAL)) {
		printf("knet_send_sync accepted invalid send_buff len (> KNET_MAX_PACKET_SIZE) or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with invalid channel (-1)\n");

	channel = -1;

	if ((!knet_send_sync(knet_h, send_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_send_sync accepted invalid channel (-1) or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with invalid channel (KNET_DATAFD_MAX)\n");

	channel = KNET_DATAFD_MAX;

	if ((!knet_send_sync(knet_h, send_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_send_sync accepted invalid channel (KNET_DATAFD_MAX) or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with unconfigured channel\n");

	channel = 0;

	if ((!knet_send_sync(knet_h, send_buff, KNET_MAX_PACKET_SIZE, channel)) || (errno != EINVAL)) {
		printf("knet_send_sync accepted invalid unconfigured channel or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with data forwarding disabled\n");

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

	if ((knet_send_sync(knet_h, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != ECANCELED)) {
		printf("knet_send_sync didn't detect datafwd disabled or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with broken dst_host_filter\n");

	if (knet_handle_setfwd(knet_h, 1) < 0) {
		printf("knet_handle_setfwd failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_handle_enable_filter(knet_h, NULL, dhost_filter) < 0) {
		printf("knet_handle_enable_filter failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	dhost_filter_ret = -1;

	if ((knet_send_sync(knet_h, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != EFAULT)) {
		printf("knet_send_sync didn't detect fatal error from dst_host_filter or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with dst_host_filter returning no host_ids_entries\n");

	dhost_filter_ret = 0;

	if ((knet_send_sync(knet_h, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != EINVAL)) {
		printf("knet_send_sync didn't detect 0 host_ids from dst_host_filter or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with host down\n");

	dhost_filter_ret = 1;

	if ((knet_send_sync(knet_h, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != EHOSTDOWN)) {
		printf("knet_send_sync didn't detect hostdown or returned incorrect error: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with dst_host_filter returning too many host_ids_entries\n");

	if (knet_host_add(knet_h, 1) < 0) {
		printf("knet_host_add failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_link_set_config(knet_h, 1, 0, KNET_TRANSPORT_UDP, &lo, &lo) < 0) {
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

	while(knet_h->host_index[1]->status.reachable != 1) {
		printf("waiting host to be reachable\n");
		sleep(1);
	}

	dhost_filter_ret = 2;

	if ((knet_send_sync(knet_h, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != E2BIG)) {
		printf("knet_send_sync didn't detect 2+ host_ids from dst_host_filter or returned incorrect error: %s\n", strerror(errno));
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with dst_host_filter returning mcast packets\n");

	dhost_filter_ret = 3;

	if ((knet_send_sync(knet_h, send_buff, KNET_MAX_PACKET_SIZE, channel) == sizeof(send_buff)) || (errno != E2BIG)) {
		printf("knet_send_sync didn't detect mcast packet from dst_host_filter or returned incorrect error: %s\n", strerror(errno));
		knet_link_set_enable(knet_h, 1, 0, 0);
		knet_link_clear_config(knet_h, 1, 0);
		knet_host_remove(knet_h, 1);
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_send_sync with valid data\n");

	dhost_filter_ret = 1;

	if (knet_send_sync(knet_h, send_buff, KNET_MAX_PACKET_SIZE, channel) < 0) {
		printf("knet_send_sync failed: %d %s\n", errno, strerror(errno));
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
