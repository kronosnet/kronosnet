/*
 * Copyright (C) 2015-2020 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "crypto.h"
#include "links.h"
#include "logging.h"
#include "transports.h"
#include "threads_common.h"
#include "threads_heartbeat.h"

static void _link_down(knet_handle_t knet_h, struct knet_host *dst_host, struct knet_link *dst_link)
{
	memset(&dst_link->pmtud_last, 0, sizeof(struct timespec));
	dst_link->received_pong = 0;
	dst_link->status.pong_last.tv_nsec = 0;
	dst_link->pong_timeout_backoff = KNET_LINK_PONG_TIMEOUT_BACKOFF;
	if (dst_link->status.connected == 1) {
		log_info(knet_h, KNET_SUB_LINK, "host: %u link: %u is down",
			 dst_host->host_id, dst_link->link_id);
		_link_updown(knet_h, dst_host->host_id, dst_link->link_id, dst_link->status.enabled, 0, 1);
	}
}

static void _handle_check_each(knet_handle_t knet_h, struct knet_host *dst_host, struct knet_link *dst_link, int timed)
{
	int err = 0, savederrno = 0, stats_err = 0;
	int len;
	ssize_t outlen = KNET_HEADER_PING_SIZE;
	struct timespec clock_now, pong_last;
	unsigned long long diff_ping;
	unsigned char *outbuf = (unsigned char *)knet_h->pingbuf;

	if (dst_link->transport_connected == 0) {
		_link_down(knet_h, dst_host, dst_link);
		return;
	}

	/* caching last pong to avoid race conditions */
	pong_last = dst_link->status.pong_last;

	if (clock_gettime(CLOCK_MONOTONIC, &clock_now) != 0) {
		log_debug(knet_h, KNET_SUB_HEARTBEAT, "Unable to get monotonic clock");
		return;
	}

	timespec_diff(dst_link->ping_last, clock_now, &diff_ping);

	if ((diff_ping >= (dst_link->ping_interval * 1000llu)) || (!timed)) {
		memmove(&knet_h->pingbuf->khp_ping_time[0], &clock_now, sizeof(struct timespec));
		knet_h->pingbuf->khp_ping_link = dst_link->link_id;
		if (pthread_mutex_lock(&knet_h->tx_seq_num_mutex)) {
			log_debug(knet_h, KNET_SUB_HEARTBEAT, "Unable to get seq mutex lock");
			return;
		}
		knet_h->pingbuf->khp_ping_seq_num = htons(knet_h->tx_seq_num);
		pthread_mutex_unlock(&knet_h->tx_seq_num_mutex);
		knet_h->pingbuf->khp_ping_timed = timed;

		if (knet_h->crypto_in_use_config) {
			if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)knet_h->pingbuf,
						    outlen,
						    knet_h->pingbuf_crypt,
						    &outlen) < 0) {
				log_debug(knet_h, KNET_SUB_HEARTBEAT, "Unable to crypto ping packet");
				return;
			}

			outbuf = knet_h->pingbuf_crypt;
			if (pthread_mutex_lock(&knet_h->handle_stats_mutex) < 0) {
				log_err(knet_h, KNET_SUB_HEARTBEAT, "Unable to get mutex lock");
				return;
			}
			knet_h->stats_extra.tx_crypt_ping_packets++;
			pthread_mutex_unlock(&knet_h->handle_stats_mutex);
		}

		stats_err = pthread_mutex_lock(&dst_link->link_stats_mutex);
		if (stats_err) {
			log_err(knet_h, KNET_SUB_HEARTBEAT, "Unable to get stats mutex lock for host %u link %u: %s",
				dst_host->host_id, dst_link->link_id, strerror(stats_err));
			return;
		}

retry:
		if (transport_get_connection_oriented(knet_h, dst_link->transport) == TRANSPORT_PROTO_NOT_CONNECTION_ORIENTED) {
			len = sendto(dst_link->outsock, outbuf, outlen,	MSG_DONTWAIT | MSG_NOSIGNAL,
				     (struct sockaddr *) &dst_link->dst_addr, sizeof(struct sockaddr_storage));
		} else {
			len = sendto(dst_link->outsock, outbuf, outlen,	MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0);
		}
		savederrno = errno;

		dst_link->ping_last = clock_now;
		dst_link->status.stats.tx_ping_packets++;
		dst_link->status.stats.tx_ping_bytes += outlen;

		if (len != outlen) {
			err = transport_tx_sock_error(knet_h, dst_link->transport, dst_link->outsock, len, savederrno);
			switch(err) {
				case -1: /* unrecoverable error */
					log_debug(knet_h, KNET_SUB_HEARTBEAT,
						  "Unable to send ping (sock: %d) packet (sendto): %d %s. recorded src ip: %s src port: %s dst ip: %s dst port: %s",
						  dst_link->outsock, savederrno, strerror(savederrno),
						  dst_link->status.src_ipaddr, dst_link->status.src_port,
						  dst_link->status.dst_ipaddr, dst_link->status.dst_port);
					dst_link->status.stats.tx_ping_errors++;
					break;
				case 0:
					break;
				case 1:
					dst_link->status.stats.tx_ping_retries++;
					goto retry;
					break;
			}
		} else {
			dst_link->last_ping_size = outlen;
		}
		pthread_mutex_unlock(&dst_link->link_stats_mutex);
	}

	timespec_diff(pong_last, clock_now, &diff_ping);
	if ((pong_last.tv_nsec) && 
	    (diff_ping >= (dst_link->pong_timeout_adj * 1000llu))) {
		_link_down(knet_h, dst_host, dst_link);
	}
}

void _send_pings(knet_handle_t knet_h, int timed)
{
	struct knet_host *dst_host;
	int link_idx;

	if (pthread_mutex_lock(&knet_h->hb_mutex)) {
		log_debug(knet_h, KNET_SUB_HEARTBEAT, "Unable to get hb mutex lock");
		return;
	}

	for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
		for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
			if ((dst_host->link[link_idx].status.enabled != 1) ||
			    (dst_host->link[link_idx].transport == KNET_TRANSPORT_LOOPBACK ) ||
			    ((dst_host->link[link_idx].dynamic == KNET_LINK_DYNIP) &&
			     (dst_host->link[link_idx].status.dynconnected != 1)))
				continue;

			_handle_check_each(knet_h, dst_host, &dst_host->link[link_idx], timed);
		}
	}

	pthread_mutex_unlock(&knet_h->hb_mutex);
}

static void _adjust_pong_timeouts(knet_handle_t knet_h)
{
	struct knet_host *dst_host;
	struct knet_link *dst_link;
	int link_idx;

	if (pthread_mutex_lock(&knet_h->backoff_mutex)) {
		log_debug(knet_h, KNET_SUB_HEARTBEAT, "Unable to get backoff_mutex");
		return;
	}

	for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
		for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
			if ((dst_host->link[link_idx].status.enabled != 1) ||
			    (dst_host->link[link_idx].transport == KNET_TRANSPORT_LOOPBACK ) ||
			    ((dst_host->link[link_idx].dynamic == KNET_LINK_DYNIP) &&
			     (dst_host->link[link_idx].status.dynconnected != 1)))
				continue;

			dst_link = &dst_host->link[link_idx];

			if (dst_link->pong_timeout_backoff > 1) {
				dst_link->pong_timeout_backoff--;
			}

			dst_link->pong_timeout_adj = (dst_link->pong_timeout * dst_link->pong_timeout_backoff) + (dst_link->status.stats.latency_ave * KNET_LINK_PONG_TIMEOUT_LAT_MUL);
		}
	}

	pthread_mutex_unlock(&knet_h->backoff_mutex);
}

void *_handle_heartbt_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	int i = 1;

	set_thread_status(knet_h, KNET_THREAD_HB, KNET_THREAD_STARTED);

	/* preparing ping buffer */
	knet_h->pingbuf->kh_version = KNET_HEADER_VERSION;
	knet_h->pingbuf->kh_type = KNET_HEADER_TYPE_PING;
	knet_h->pingbuf->kh_node = htons(knet_h->host_id);

	while (!shutdown_in_progress(knet_h)) {
		usleep(knet_h->threads_timer_res);

		if (pthread_rwlock_rdlock(&knet_h->global_rwlock) != 0) {
			log_debug(knet_h, KNET_SUB_HEARTBEAT, "Unable to get read lock");
			continue;
		}

		/*
		 *  _adjust_pong_timeouts should execute approx once a second.
		 */
		if ((i % (1000000 / knet_h->threads_timer_res)) == 0) {
			_adjust_pong_timeouts(knet_h);
			i = 1;
		} else {
			i++;
		}

		_send_pings(knet_h, 1);

		pthread_rwlock_unlock(&knet_h->global_rwlock);
	}

	set_thread_status(knet_h, KNET_THREAD_HB, KNET_THREAD_STOPPED);

	return NULL;
}
