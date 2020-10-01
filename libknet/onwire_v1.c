/*
 * Copyright (C) 2020 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "logging.h"
#include "host.h"
#include "links.h"
#include "onwire_v1.h"

int prep_ping_v1(knet_handle_t knet_h, struct knet_link *dst_link, uint8_t onwire_ver, struct timespec clock_now, int timed, ssize_t *outlen)
{
	*outlen = KNET_HEADER_PING_V1_SIZE;

	/* preparing ping buffer */
	knet_h->pingbuf->kh_version = onwire_ver;
	knet_h->pingbuf->kh_max_ver = knet_h->onwire_max_ver;
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

struct knet_link *get_link_from_pong_v1(knet_handle_t knet_h, struct knet_host *src_host, struct knet_header *inbuf)
{
	return &src_host->link[inbuf->khp_ping_v1_link];
}

void prep_pmtud_v1(knet_handle_t knet_h, struct knet_link *dst_link, uint8_t onwire_ver, size_t onwire_len)
{
	knet_h->pmtudbuf->kh_version = onwire_ver;
	knet_h->pmtudbuf->kh_max_ver = knet_h->onwire_max_ver;
	knet_h->pmtudbuf->kh_type = KNET_HEADER_TYPE_PMTUD;
	knet_h->pmtudbuf->kh_node = htons(knet_h->host_id);
	knet_h->pmtudbuf->khp_pmtud_v1_link = dst_link->link_id;
	knet_h->pmtudbuf->khp_pmtud_v1_size = onwire_len;
}

void prep_pmtud_reply_v1(knet_handle_t knet_h, struct knet_header *inbuf, ssize_t *outlen)
{
	*outlen = KNET_HEADER_PMTUD_V1_SIZE;
	inbuf->kh_type = KNET_HEADER_TYPE_PMTUD_REPLY;
	inbuf->kh_node = htons(knet_h->host_id);
}

void process_pmtud_reply_v1(knet_handle_t knet_h, struct knet_link *src_link, struct knet_header *inbuf)
{
	src_link->last_recv_mtu = inbuf->khp_pmtud_v1_size;
}

void prep_tx_bufs_v1(knet_handle_t knet_h,
		     struct knet_header *inbuf, unsigned char *data, size_t inlen, unsigned int temp_data_mtu,
		     seq_num_t tx_seq_num, int8_t channel, int bcast, int data_compressed,
		     int *msgs_to_send, struct iovec iov_out[PCKT_FRAG_MAX][2], int *iovcnt_out)
{
	uint8_t frag_idx = 0;
	size_t frag_len = inlen;

	/*
	 * prepare the main header
	 */
	inbuf->kh_type = KNET_HEADER_TYPE_DATA;
	inbuf->kh_version = 1;
	inbuf->kh_max_ver = knet_h->onwire_max_ver;
	inbuf->kh_node = htons(knet_h->host_id);

	/*
	 * prepare the data header
	 */
	inbuf->khp_data_v1_frag_seq = 0;
	inbuf->khp_data_v1_bcast = bcast;
	inbuf->khp_data_v1_frag_num = ceil((float)inlen / temp_data_mtu);
	inbuf->khp_data_v1_channel = channel;
	inbuf->khp_data_v1_seq_num = htons(tx_seq_num);
	if (data_compressed) {
		inbuf->khp_data_v1_compress = knet_h->compress_model;
	} else {
		inbuf->khp_data_v1_compress = 0;
	}

	/*
	 * handle fragmentation
	 */
	if (inbuf->khp_data_v1_frag_num > 1) {
		while (frag_idx < inbuf->khp_data_v1_frag_num) {
			/*
			 * set the iov_base
			 */
			iov_out[frag_idx][0].iov_base = (void *)knet_h->send_to_links_buf[frag_idx];
			iov_out[frag_idx][0].iov_len = KNET_HEADER_DATA_V1_SIZE;
			iov_out[frag_idx][1].iov_base = data + (temp_data_mtu * frag_idx);

			/*
			 * set the len
			 */
			if (frag_len > temp_data_mtu) {
				iov_out[frag_idx][1].iov_len = temp_data_mtu;
			} else {
				iov_out[frag_idx][1].iov_len = frag_len;
			}

			/*
			 * copy the frag info on all buffers
			 */
			memmove(knet_h->send_to_links_buf[frag_idx], inbuf, KNET_HEADER_DATA_V1_SIZE);
			/*
			 * bump the frag
			 */
			knet_h->send_to_links_buf[frag_idx]->khp_data_v1_frag_seq = frag_idx + 1;

			frag_len = frag_len - temp_data_mtu;
			frag_idx++;
		}
		*iovcnt_out = 2;
	} else {
		iov_out[frag_idx][0].iov_base = (void *)inbuf;
		iov_out[frag_idx][0].iov_len = frag_len + KNET_HEADER_DATA_V1_SIZE;
		*iovcnt_out = 1;
	}
	*msgs_to_send = inbuf->khp_data_v1_frag_num;
}

unsigned char *get_data_v1(knet_handle_t knet_h, struct knet_header *inbuf)
{
	return inbuf->khp_data_v1_userdata;
}

void get_data_header_info_v1(knet_handle_t knet_h, struct knet_header *inbuf,
			     ssize_t *header_size, int8_t *channel,
			     seq_num_t *seq_num, uint8_t *decompress_type,
			     uint8_t *frags, uint8_t *frag_seq)
{
	*header_size = KNET_HEADER_DATA_V1_SIZE;
	*channel = inbuf->khp_data_v1_channel;
	*seq_num = ntohs(inbuf->khp_data_v1_seq_num);
	*decompress_type = inbuf->khp_data_v1_compress;
	*frags = inbuf->khp_data_v1_frag_num;
	*frag_seq = inbuf->khp_data_v1_frag_seq;
}
