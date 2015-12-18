/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "crypto.h"
#include "link.h"
#include "logging.h"
#include "threads_common.h"
#include "threads_pmtud.h"

static void _handle_check_pmtud(knet_handle_t knet_h, struct knet_host *dst_host, struct knet_link *dst_link)
{
	int ret, savederrno, mutex_retry_limit, failsafe;
	ssize_t onwire_len;   /* current packet onwire size */
	ssize_t overhead_len; /* onwire packet overhead (protocol based) */
	ssize_t max_mtu_len;  /* max mtu for protocol */
	ssize_t data_len;     /* how much data we can send in the packet
			       * generally would be onwire_len - overhead_len
			       * needs to be adjusted for crypto
			       */
	ssize_t pad_len;      /* crypto packet pad size, needs to move into crypto.c callbacks */
	int len;	      /* len of what we were able to sendto onwire */

	struct timespec ts;
	unsigned char *outbuf = (unsigned char *)knet_h->pmtudbuf;

	mutex_retry_limit = 0;
	failsafe = 0;
	pad_len = 0;

	dst_link->last_bad_mtu = 0;

	knet_h->pmtudbuf->khp_pmtud_link = dst_link->link_id;

	switch (dst_link->dst_addr.ss_family) {
		case AF_INET6:
			max_mtu_len = KNET_PMTUD_SIZE_V6;
			overhead_len = KNET_PMTUD_OVERHEAD_V6;
			dst_link->last_good_mtu = KNET_PMTUD_MIN_MTU_V6;
			break;
		case AF_INET:
			max_mtu_len = KNET_PMTUD_SIZE_V4;
			overhead_len = KNET_PMTUD_OVERHEAD_V4;
			dst_link->last_good_mtu = KNET_PMTUD_MIN_MTU_V4;
			break;
		default:
			return;
	}

	/*
	 * discovery starts from the top because kernel will
	 * refuse to send packets > current iface mtu.
	 * this saves us some time and network bw.
	 */ 
	onwire_len = max_mtu_len;

restart:

	/*
	 * prevent a race when interface mtu is changed _exactly_ during
	 * the discovery process and it's complex to detect. Easier
	 * to wait the next loop.
	 * 30 is not an arbitrary value. To bisect from 576 to 128000 doesn't
	 * take more than 18/19 steps.
	 */

	if (failsafe == 30) {
		log_err(knet_h, KNET_SUB_PMTUD_T,
			"Aborting PMTUD process: Too many attempts. MTU might have changed during discovery.");
		return;
	} else {
		failsafe++;
	}

	data_len = onwire_len - overhead_len;

	if (knet_h->crypto_instance) {

		if (knet_h->sec_block_size) {
			pad_len = knet_h->sec_block_size - (data_len % knet_h->sec_block_size);
			if (pad_len == knet_h->sec_block_size) {
				pad_len = 0;
			}
			data_len = data_len + pad_len;
		}

		data_len = data_len + (knet_h->sec_hash_size + knet_h->sec_salt_size + knet_h->sec_block_size);

		if (knet_h->sec_block_size) {
			while (data_len + overhead_len >= max_mtu_len) {
				data_len = data_len - knet_h->sec_block_size;
			}
		}

		if (dst_link->last_bad_mtu) {
			while (data_len + overhead_len >= dst_link->last_bad_mtu) {
				data_len = data_len - (knet_h->sec_hash_size + knet_h->sec_salt_size + knet_h->sec_block_size);
			}
		}

		onwire_len = data_len + overhead_len;
		knet_h->pmtudbuf->khp_pmtud_size = onwire_len;

		if (crypto_encrypt_and_sign(knet_h,
					    (const unsigned char *)knet_h->pmtudbuf,
					    data_len - (knet_h->sec_hash_size + knet_h->sec_salt_size + knet_h->sec_block_size),
					    knet_h->pmtudbuf_crypt,
					    &data_len) < 0) {
			log_debug(knet_h, KNET_SUB_PMTUD_T, "Unable to crypto pmtud packet");
			return;
		}

		outbuf = knet_h->pmtudbuf_crypt;

	} else {

		knet_h->pmtudbuf->khp_pmtud_size = onwire_len;

	}

	/* link has gone down, aborting pmtud */
	if (dst_link->status.connected != 1) {
		return;
	}

	if (pthread_mutex_lock(&knet_h->pmtud_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_PMTUD_T, "Unable to get mutex lock");
		return;
	}

	len = sendto(dst_link->listener_sock, outbuf, data_len,
			MSG_DONTWAIT, (struct sockaddr *) &dst_link->dst_addr,
			sizeof(struct sockaddr_storage));
	savederrno = errno;

	if ((len < 0) && (savederrno != EMSGSIZE)) {
		log_debug(knet_h, KNET_SUB_PMTUD_T, "Unable to send pmtu packet (sendto): %d %s", savederrno, strerror(savederrno));
		pthread_mutex_unlock(&knet_h->pmtud_mutex);
		return;
	}

	if (len != data_len) {
		/*
		 * this is coming from "localhost" already.
		 */
		if (savederrno == EMSGSIZE) {
			dst_link->last_bad_mtu = onwire_len;
		} else {
			log_debug(knet_h, KNET_SUB_PMTUD_T, "Unable to send pmtu packet len: %zu err: %s", onwire_len, strerror(savederrno));
		}
	} else {
		dst_link->last_sent_mtu = onwire_len;
		dst_link->last_recv_mtu = 0;

		if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
			log_debug(knet_h, KNET_SUB_PMTUD_T, "Unable to get current time: %s", strerror(errno));
			pthread_mutex_unlock(&knet_h->pmtud_mutex);
			return;
		}

		/*
		 * We should probably adjust this by 4x current known latency
		 * but for now 2 seconds time out are a good match.
		 */ 
		ts.tv_sec += 2;
		ret = pthread_cond_timedwait(&knet_h->pmtud_cond, &knet_h->pmtud_mutex, &ts);

		if (knet_h->fini_in_progress) {
			pthread_mutex_unlock(&knet_h->pmtud_mutex);
			return;
		}

		if ((ret != 0) && (ret != ETIMEDOUT)) {
			pthread_mutex_unlock(&knet_h->pmtud_mutex);
			if (mutex_retry_limit == 3) {
				return;
			}
			mutex_retry_limit++;
			goto restart;
		}

		if ((dst_link->last_recv_mtu != onwire_len) || (ret)) {
			dst_link->last_bad_mtu = onwire_len;
		} else {
			int found_mtu = 0;

			if (knet_h->sec_block_size) {
				if ((onwire_len + knet_h->sec_block_size >= max_mtu_len) ||
				   ((dst_link->last_bad_mtu) && (dst_link->last_bad_mtu <= (onwire_len + knet_h->sec_block_size)))) {
					found_mtu = 1;
				}
			} else {
				if ((onwire_len == max_mtu_len) ||
				    ((dst_link->last_bad_mtu) && (dst_link->last_bad_mtu == (onwire_len + 1)))) {
					found_mtu = 1;
				}
			}

			if (found_mtu) {
				/*
				 * account for IP overhead in PMTU calculation
				 */
				dst_link->status.mtu = onwire_len - overhead_len;
				pthread_mutex_unlock(&knet_h->pmtud_mutex);
				return;
			}

			dst_link->last_good_mtu = onwire_len;
		}
	}

	onwire_len = (dst_link->last_good_mtu + dst_link->last_bad_mtu) / 2;
	pthread_mutex_unlock(&knet_h->pmtud_mutex);

	goto restart;
}

void *_handle_pmtud_link_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	struct knet_host *dst_host;
	struct knet_link *dst_link;
	int link_idx;
	unsigned int saved_pmtud, min_mtu, have_mtu;
	struct timespec ts;
	int ret, have_timer;
	unsigned int old_interval;

	knet_h->link_mtu = KNET_PMTUD_MIN_MTU_V4;

	/* preparing pmtu buffer */
	knet_h->pmtudbuf->kh_version = KNET_HEADER_VERSION;
	knet_h->pmtudbuf->kh_type = KNET_HEADER_TYPE_PMTUD;
	knet_h->pmtudbuf->kh_node = htons(knet_h->host_id);

	while (!knet_h->fini_in_progress) {
		/*
		 * make this also triggered by link status changes
		 */
timer_restart:

		have_timer = 0;

		if (!pthread_mutex_lock(&knet_h->pmtud_timer_mutex)) {
			if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
				log_debug(knet_h, KNET_SUB_PMTUD_T, "Unable to get current time: %s", strerror(errno));
				pthread_mutex_unlock(&knet_h->pmtud_timer_mutex);
			} else {
				old_interval = knet_h->pmtud_interval;
				ts.tv_sec += knet_h->pmtud_interval;

				ret = pthread_cond_timedwait(&knet_h->pmtud_timer_cond, &knet_h->pmtud_timer_mutex, &ts);

				if (knet_h->pmtud_fini_requested) {
					pthread_mutex_unlock(&knet_h->pmtud_timer_mutex);
					goto interrupt;
				}

				if ((ret != 0) && (ret != ETIMEDOUT)) {
					log_debug(knet_h, KNET_SUB_PMTUD_T, "Unable to wait for PMTUd timer cond/mutex");
				} else {
					have_timer = 1;
					if (old_interval != knet_h->pmtud_interval) {
						log_debug(knet_h, KNET_SUB_PMTUD_T, "PMTUd interval change detected, restarting");
						pthread_mutex_unlock(&knet_h->pmtud_timer_mutex);
						goto timer_restart;
					}
				}
				pthread_mutex_unlock(&knet_h->pmtud_timer_mutex);
			}
		}

		if (!have_timer) {
			log_debug(knet_h, KNET_SUB_PMTUD_T, "Sleeping %u seconds", knet_h->pmtud_interval);
			sleep(knet_h->pmtud_interval);
		}

		min_mtu = KNET_PMTUD_SIZE_V4;
		have_mtu = 0;

		if (knet_h->pmtud_fini_requested)
			continue;

		if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0) {
			log_debug(knet_h, KNET_SUB_PMTUD_T, "Unable to get read lock");
			continue;
		}

		for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
			for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
				dst_link = &dst_host->link[link_idx];
				if ((dst_link->status.enabled != 1) ||
				    (dst_link->status.connected != 1) ||
				    ((dst_link->dynamic == KNET_LINK_DYNIP) &&
				     (dst_link->status.dynconnected != 1)))
					continue;

				if (knet_h->pmtud_fini_requested)
					goto interrupt;

				saved_pmtud = dst_link->status.mtu;
				log_debug(knet_h, KNET_SUB_PMTUD_T, "Starting PMTUD for host: %u link: %u", dst_host->host_id, link_idx);
				_handle_check_pmtud(knet_h, dst_host, dst_link);
				if ((saved_pmtud) && (saved_pmtud != dst_link->status.mtu)) {
					log_info(knet_h, KNET_SUB_PMTUD_T, "PMTUD link change for host: %u link: %u from %u to %u",
						 dst_host->host_id, link_idx, saved_pmtud, dst_link->status.mtu);
				}
				log_debug(knet_h, KNET_SUB_PMTUD_T, "PMTUD completed for host: %u link: %u current link mtu: %u iface mtu: %u",
					  dst_host->host_id, link_idx, dst_link->status.mtu,
					  (dst_link->dst_addr.ss_family == AF_INET) ?
						dst_link->status.mtu + KNET_PMTUD_OVERHEAD_V4 :
						dst_link->status.mtu + KNET_PMTUD_OVERHEAD_V6);
				if (dst_link->status.mtu < min_mtu) {
					min_mtu = dst_link->status.mtu;
				}
				have_mtu = 1;
			}
		}

		if (have_mtu) {
			if (knet_h->link_mtu != min_mtu) {
				log_info(knet_h, KNET_SUB_PMTUD_T, "Global link MTU changed from: %u to %u", knet_h->link_mtu, min_mtu);
				knet_h->link_mtu = min_mtu;
				knet_h->data_mtu = min_mtu - KNET_HEADER_ALL_SIZE - knet_h->sec_header_size;
				log_info(knet_h, KNET_SUB_PMTUD_T, "Global data MTU changed to: %u", knet_h->data_mtu);

				if (knet_h->pmtud_notify_fn) {
					knet_h->pmtud_notify_fn(knet_h->pmtud_notify_fn_private_data,
								knet_h->link_mtu, knet_h->data_mtu);
				}
			}
		} else {
			log_info(knet_h, KNET_SUB_PMTUD_T, "No MTU information available.");
		}

interrupt:
		pthread_rwlock_unlock(&knet_h->list_rwlock);
	}

	return NULL;
}
