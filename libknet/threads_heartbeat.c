/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#include <sys/uio.h>
#include <math.h>

#include "internals.h"
#include "onwire.h"
#include "crypto.h"
#include "common.h"
#include "host.h"
#include "logging.h"
#include "listener.h"
#include "link.h"
#include "threads_common.h"
#include "threads_heartbeat.h"

#define KNET_PING_TIMERES 200000

static void _handle_check_each(knet_handle_t knet_h, struct knet_host *dst_host, struct knet_link *dst_link)
{
	int len;
	ssize_t outlen = KNET_HEADER_PING_SIZE;
	struct timespec clock_now, pong_last;
	unsigned long long diff_ping;
	unsigned char *outbuf = (unsigned char *)knet_h->pingbuf;

	/* caching last pong to avoid race conditions */
	pong_last = dst_link->status.pong_last;

	if (clock_gettime(CLOCK_MONOTONIC, &clock_now) != 0) {
		log_debug(knet_h, KNET_SUB_HB_T, "Unable to get monotonic clock");
		return;
	}

	timespec_diff(dst_link->ping_last, clock_now, &diff_ping);

	if (diff_ping >= (dst_link->ping_interval * 1000llu)) {
		memcpy(&knet_h->pingbuf->khp_ping_time[0], &clock_now, sizeof(struct timespec));
		knet_h->pingbuf->khp_ping_link = dst_link->link_id;

		if (knet_h->crypto_instance) {
			if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)knet_h->pingbuf,
						    outlen,
						    knet_h->pingbuf_crypt,
						    &outlen) < 0) {
				log_debug(knet_h, KNET_SUB_HB_T, "Unable to crypto ping packet");
				return;
			}

			outbuf = knet_h->pingbuf_crypt;
		}

		len = sendto(dst_link->listener_sock, outbuf, outlen,
			MSG_DONTWAIT, (struct sockaddr *) &dst_link->dst_addr,
			sizeof(struct sockaddr_storage));

		dst_link->ping_last = clock_now;

		if (len != outlen) {
			log_debug(knet_h, KNET_SUB_HB_T,
				  "Unable to send ping (sock: %d) packet (sendto): %d %s\nrecorded src ip: %s src port: %s dst ip: %s dst port: %s",
				  dst_link->listener_sock, errno, strerror(errno),
				  dst_link->status.src_ipaddr, dst_link->status.src_port,
				  dst_link->status.dst_ipaddr, dst_link->status.dst_port);
		}
	}

	timespec_diff(pong_last, clock_now, &diff_ping);
	if ((pong_last.tv_nsec) && 
	    (diff_ping >= (dst_link->pong_timeout * 1000llu))) {
		dst_link->received_pong = 0;
		dst_link->status.pong_last.tv_nsec = 0;
		if (dst_link->status.connected == 1) {
			log_info(knet_h, KNET_SUB_LINK, "host: %u link: %u is down",
				 dst_host->host_id, dst_link->link_id);
			_link_updown(knet_h, dst_host->host_id, dst_link->link_id, dst_link->status.enabled, 0);
		}
	}
}

void *_handle_heartbt_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	struct knet_host *dst_host;
	int link_idx;

	/* preparing ping buffer */
	knet_h->pingbuf->kh_version = KNET_HEADER_VERSION;
	knet_h->pingbuf->kh_type = KNET_HEADER_TYPE_PING;
	knet_h->pingbuf->kh_node = htons(knet_h->host_id);

	while (!knet_h->fini_in_progress) {
		usleep(KNET_PING_TIMERES);

		if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0) {
			log_debug(knet_h, KNET_SUB_HB_T, "Unable to get read lock");
			continue;
		}

		for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
			for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
				if ((dst_host->link[link_idx].status.enabled != 1) ||
				    ((dst_host->link[link_idx].dynamic == KNET_LINK_DYNIP) &&
				     (dst_host->link[link_idx].status.dynconnected != 1)))
					continue;
				_handle_check_each(knet_h, dst_host, &dst_host->link[link_idx]);
			}
		}

		pthread_rwlock_unlock(&knet_h->list_rwlock);
	}

	return NULL;
}

