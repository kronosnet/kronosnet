/*
 * Copyright (C) 2020-2024 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_ONWIRE_V1_H__
#define __KNET_ONWIRE_V1_H__

#include <stdint.h>

#include "internals.h"

int prep_ping_v1(knet_handle_t knet_h, struct knet_link *dst_link, uint8_t onwire_ver, struct timespec clock_now, int timed, ssize_t *outlen);
void prep_pong_v1(knet_handle_t knet_h, struct knet_header *inbuf, ssize_t *outlen);
void process_ping_v1(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link, struct knet_header *inbuf, ssize_t len);
void process_pong_v1(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link, struct knet_header *inbuf, struct timespec *recvtime);
struct knet_link *get_link_from_pong_v1(knet_handle_t knet_h, struct knet_host *src_host, struct knet_header *inbuf);

void prep_pmtud_v1(knet_handle_t knet_h, struct knet_link *dst_link, uint8_t onwire_ver, size_t onwire_len, size_t data_len);
void prep_pmtud_reply_v1(knet_handle_t knet_h, struct knet_header *inbuf, ssize_t *outlen);
void process_pmtud_reply_v1(knet_handle_t knet_h, struct knet_link *src_link, struct knet_header *inbuf);

void prep_tx_bufs_v1(knet_handle_t knet_h,
		     struct knet_header *inbuf, unsigned char *data, size_t inlen, uint32_t data_checksum, unsigned int temp_data_mtu,
		     seq_num_t tx_seq_num, int8_t channel, int bcast, int data_compressed,
		     int *msgs_to_send, struct iovec iov_out[PCKT_FRAG_MAX][2], int *iovcnt_out);

unsigned char *get_data_v1(knet_handle_t knet_h, struct knet_header *inbuf);

void get_data_header_info_v1(knet_handle_t knet_h, struct knet_header *inbuf,
			     ssize_t *header_size, int8_t *channel,
			     seq_num_t *seq_num, uint8_t *decompress_type,
			     uint8_t *frags, uint8_t *frag_seq);
#endif
