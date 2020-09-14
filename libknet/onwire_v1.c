/*
 * Copyright (C) 2020 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "logging.h"
#include "host.h"
#include "links.h"

int prep_ping_v1(knet_handle_t knet_h, struct knet_link *dst_link, uint8_t onwire_ver, struct timespec clock_now, int timed, ssize_t *outlen)
{
	*outlen = KNET_HEADER_PING_V1_SIZE;

	/* preparing ping buffer */
	knet_h->pingbuf->kh_version = onwire_ver;
	knet_h->pingbuf->kh_max_ver = KNET_HEADER_ONWIRE_MAX_VER;
	knet_h->pingbuf->kh_type = KNET_HEADER_TYPE_PING;
	knet_h->pingbuf->kh_node = htons(knet_h->host_id);
	knet_h->pingbuf->khp_ping_v1_link = dst_link->link_id;
	knet_h->pingbuf->khp_ping_v1_timed = timed;
	memmove(&knet_h->pingbuf->khp_ping_v1_time[0], &clock_now, sizeof(struct timespec));

	if (pthread_mutex_lock(&knet_h->tx_seq_num_mutex)) {
		log_debug(knet_h, KNET_SUB_HEARTBEAT, "Unable to get seq mutex lock");
		return -1;
	}
	knet_h->pingbuf->khp_ping_v1_seq_num = htons(knet_h->tx_seq_num);
	pthread_mutex_unlock(&knet_h->tx_seq_num_mutex);

	return 0;
}

void prep_pong_v1(knet_handle_t knet_h, struct knet_header *inbuf, ssize_t *outlen)
{
	*outlen = KNET_HEADER_PING_V1_SIZE;
	inbuf->kh_type = KNET_HEADER_TYPE_PONG;
	inbuf->kh_node = htons(knet_h->host_id);
}

void process_ping_v1(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link, struct knet_header *inbuf, ssize_t len)
{
	int wipe_bufs = 0;
	seq_num_t recv_seq_num = ntohs(inbuf->khp_ping_v1_seq_num);

	if (!inbuf->khp_ping_v1_timed) {
		/*
		 * we might be receiving this message from all links, but we want
		 * to process it only the first time
		 */
		if (recv_seq_num != src_host->untimed_rx_seq_num) {
			/*
			 * cache the untimed seq num
			 */
			src_host->untimed_rx_seq_num = recv_seq_num;
			/*
			 * if the host has received data in between
			 * untimed ping, then we don't need to wipe the bufs
			 */
			if (src_host->got_data) {
				src_host->got_data = 0;
				wipe_bufs = 0;
			} else {
				wipe_bufs = 1;
			}
		}
		_seq_num_lookup(src_host, recv_seq_num, 0, wipe_bufs);
	} else {
		/*
		 * pings always arrives in bursts over all the link
		 * catch the first of them to cache the seq num and
		 * avoid duplicate processing
		 */
		if (recv_seq_num != src_host->timed_rx_seq_num) {
			src_host->timed_rx_seq_num = recv_seq_num;

			if (recv_seq_num == 0) {
				_seq_num_lookup(src_host, recv_seq_num, 0, 1);
			}
		}
	}
}

void process_pong_v1(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link, struct knet_header *inbuf, struct timespec *recvtime)
{
	memmove(recvtime, &inbuf->khp_ping_v1_time[0], sizeof(struct timespec));
}
