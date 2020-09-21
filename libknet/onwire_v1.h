/*
 * Copyright (C) 2020 Red Hat, Inc.  All rights reserved.
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

void prep_pmtud_v1(knet_handle_t knet_h, struct knet_link *dst_link, uint8_t onwire_ver, size_t onwire_len);
void prep_pmtud_reply_v1(knet_handle_t knet_h, struct knet_header *inbuf, ssize_t *outlen);
void process_pmtud_reply_v1(knet_handle_t knet_h, struct knet_link *src_link, struct knet_header *inbuf);

#endif
