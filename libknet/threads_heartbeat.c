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
#include "host.h"
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

static void send_ping(knet_handle_t knet_h, struct knet_host *dst_host, struct knet_link *dst_link, int timed)
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
		/* preparing ping buffer */
		knet_h->pingbuf->kh_version = knet_h->onwire_ver;
		knet_h->pingbuf->kh_max_ver = KNET_HEADER_ONWIRE_MAX_VER;
		knet_h->pingbuf->kh_type = KNET_HEADER_TYPE_PING;
		knet_h->pingbuf->kh_node = htons(knet_h->host_id);

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

static void send_pong(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link, struct knet_header *inbuf) {
	int err = 0, savederrno = 0, stats_err = 0;
	unsigned char *outbuf = (unsigned char *)inbuf;
	ssize_t len, outlen;

	outlen = KNET_HEADER_PING_SIZE;
	inbuf->kh_type = KNET_HEADER_TYPE_PONG;
	inbuf->kh_node = htons(knet_h->host_id);

	if (knet_h->crypto_in_use_config) {
		if (crypto_encrypt_and_sign(knet_h,
					    (const unsigned char *)inbuf,
					    outlen,
					    knet_h->recv_from_links_buf_crypt,
					    &outlen) < 0) {
			log_debug(knet_h, KNET_SUB_HEARTBEAT, "Unable to encrypt pong packet");
			return;
		}
		outbuf = knet_h->recv_from_links_buf_crypt;
		stats_err = pthread_mutex_lock(&knet_h->handle_stats_mutex);
		if (stats_err < 0) {
			log_err(knet_h, KNET_SUB_HEARTBEAT, "Unable to get mutex lock: %s", strerror(stats_err));
			return;
		}
		knet_h->stats_extra.tx_crypt_pong_packets++;
		pthread_mutex_unlock(&knet_h->handle_stats_mutex);
	}

retry:
	if (src_link->transport_connected) {
		if (transport_get_connection_oriented(knet_h, src_link->transport) == TRANSPORT_PROTO_NOT_CONNECTION_ORIENTED) {
			len = sendto(src_link->outsock, outbuf, outlen, MSG_DONTWAIT | MSG_NOSIGNAL,
				     (struct sockaddr *) &src_link->dst_addr, sizeof(struct sockaddr_storage));
		} else {
			len = sendto(src_link->outsock, outbuf, outlen, MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0);
		}
		savederrno = errno;
		if (len != outlen) {
			err = transport_tx_sock_error(knet_h, src_link->transport, src_link->outsock, len, savederrno);
			switch(err) {
				case -1: /* unrecoverable error */
					log_debug(knet_h, KNET_SUB_HEARTBEAT,
						  "Unable to send pong reply (sock: %d) packet (sendto): %d %s. recorded src ip: %s src port: %s dst ip: %s dst port: %s",
						  src_link->outsock, errno, strerror(errno),
						  src_link->status.src_ipaddr, src_link->status.src_port,
						  src_link->status.dst_ipaddr, src_link->status.dst_port);
					src_link->status.stats.tx_pong_errors++;
					break;
				case 0: /* ignore error and continue */
					break;
				case 1: /* retry to send those same data */
					src_link->status.stats.tx_pong_retries++;
					goto retry;
					break;
			}
		}
		src_link->status.stats.tx_pong_packets++;
		src_link->status.stats.tx_pong_bytes += outlen;
	}
}

void process_ping(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link, struct knet_header *inbuf, ssize_t len) {
	int wipe_bufs = 0;
	seq_num_t recv_seq_num = ntohs(inbuf->khp_ping_seq_num);

	src_link->status.stats.rx_ping_packets++;
	src_link->status.stats.rx_ping_bytes += len;

	if (!inbuf->khp_ping_timed) {
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

	send_pong(knet_h, src_host, src_link, inbuf);
}

void process_pong(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link, struct knet_header *inbuf, ssize_t len) {
	struct timespec recvtime;
	unsigned long long latency_last;

	src_link->status.stats.rx_pong_packets++;
	src_link->status.stats.rx_pong_bytes += len;
	clock_gettime(CLOCK_MONOTONIC, &src_link->status.pong_last);

	memmove(&recvtime, &inbuf->khp_ping_time[0], sizeof(struct timespec));
	timespec_diff(recvtime,
		      src_link->status.pong_last, &latency_last);

	if ((latency_last / 1000llu) > src_link->pong_timeout) {
		log_debug(knet_h, KNET_SUB_RX,
			  "Incoming pong packet from host: %u link: %u has higher latency than pong_timeout. Discarding",
			  src_host->host_id, src_link->link_id);
	} else {

		/*
		 * in words : ('previous mean' * '(count -1)') + 'new value') / 'count'
		 */

		src_link->status.stats.latency_samples++;

		/*
		 * limit to max_samples (precision)
		 */
		if (src_link->status.stats.latency_samples >= src_link->latency_max_samples) {
			src_link->status.stats.latency_samples = src_link->latency_max_samples;
		}
		src_link->status.stats.latency_ave =
			(((src_link->status.stats.latency_ave * (src_link->status.stats.latency_samples - 1)) + (latency_last / 1000llu)) / src_link->status.stats.latency_samples);

		if (src_link->status.stats.latency_ave < src_link->pong_timeout_adj) {
			if (!src_link->status.connected) {
				if (src_link->received_pong >= src_link->pong_count) {
					log_info(knet_h, KNET_SUB_RX, "host: %u link: %u is up",
						 src_host->host_id, src_link->link_id);
					_link_updown(knet_h, src_host->host_id, src_link->link_id, src_link->status.enabled, 1, 0);
				} else {
					src_link->received_pong++;
					log_debug(knet_h, KNET_SUB_RX, "host: %u link: %u received pong: %u",
						  src_host->host_id, src_link->link_id, src_link->received_pong);
				}
			}
		}
		/* Calculate latency stats */
		if (src_link->status.stats.latency_ave > src_link->status.stats.latency_max) {
			src_link->status.stats.latency_max = src_link->status.stats.latency_ave;
		}
		if (src_link->status.stats.latency_ave < src_link->status.stats.latency_min) {
			src_link->status.stats.latency_min = src_link->status.stats.latency_ave;
		}
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

			send_ping(knet_h, dst_host, &dst_host->link[link_idx], timed);
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
