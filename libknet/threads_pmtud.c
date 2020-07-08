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
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "crypto.h"
#include "links.h"
#include "host.h"
#include "logging.h"
#include "transports.h"
#include "threads_common.h"
#include "threads_pmtud.h"

static int _calculate_manual_mtu(knet_handle_t knet_h, struct knet_link *dst_link)
{
	size_t ipproto_overhead_len;	/* onwire packet overhead (protocol based) */

	switch (dst_link->dst_addr.ss_family) {
		case AF_INET6:
			ipproto_overhead_len = KNET_PMTUD_OVERHEAD_V6 + dst_link->proto_overhead;
			break;
		case AF_INET:
			ipproto_overhead_len = KNET_PMTUD_OVERHEAD_V4 + dst_link->proto_overhead;
			break;
		default:
			log_debug(knet_h, KNET_SUB_PMTUD, "unknown protocol");
			return 0;
			break;
	}

	dst_link->status.mtu = calc_max_data_outlen(knet_h, knet_h->manual_mtu - ipproto_overhead_len);

	return 1;
}

static int _handle_check_link_pmtud(knet_handle_t knet_h, struct knet_host *dst_host, struct knet_link *dst_link)
{
	int err, ret, savederrno, mutex_retry_limit, failsafe, use_kernel_mtu, warn_once;
	uint32_t kernel_mtu;		/* record kernel_mtu from EMSGSIZE */
	size_t onwire_len;   		/* current packet onwire size */
	size_t ipproto_overhead_len;	/* onwire packet overhead (protocol based) */
	size_t max_mtu_len;		/* max mtu for protocol */
	size_t data_len;		/* how much data we can send in the packet
					 * generally would be onwire_len - ipproto_overhead_len
					 * needs to be adjusted for crypto
					 */
	size_t app_mtu_len;		/* real data that we can send onwire */
	ssize_t len;			/* len of what we were able to sendto onwire */

	struct timespec ts, pmtud_crypto_start_ts, pmtud_crypto_stop_ts;
	unsigned long long pong_timeout_adj_tmp, timediff;
	int pmtud_crypto_reduce = 1;
	unsigned char *outbuf = (unsigned char *)knet_h->pmtudbuf;

	warn_once = 0;

	mutex_retry_limit = 0;
	failsafe = 0;

	knet_h->pmtudbuf->khp_pmtud_link = dst_link->link_id;

	switch (dst_link->dst_addr.ss_family) {
		case AF_INET6:
			max_mtu_len = KNET_PMTUD_SIZE_V6;
			ipproto_overhead_len = KNET_PMTUD_OVERHEAD_V6 + dst_link->proto_overhead;
			break;
		case AF_INET:
			max_mtu_len = KNET_PMTUD_SIZE_V4;
			ipproto_overhead_len = KNET_PMTUD_OVERHEAD_V4 + dst_link->proto_overhead;
			break;
		default:
			log_debug(knet_h, KNET_SUB_PMTUD, "PMTUD aborted, unknown protocol");
			return -1;
			break;
	}

	dst_link->last_bad_mtu = 0;
	dst_link->last_good_mtu = dst_link->last_ping_size + ipproto_overhead_len;

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
		log_err(knet_h, KNET_SUB_PMTUD,
			"Aborting PMTUD process: Too many attempts. MTU might have changed during discovery.");
		return -1;
	} else {
		failsafe++;
	}

	/*
	 * common to all packets
	 */

	/*
	 * calculate the application MTU based on current onwire_len minus ipproto_overhead_len
	 */

	app_mtu_len = calc_max_data_outlen(knet_h, onwire_len - ipproto_overhead_len);

	/*
	 * recalculate onwire len back that might be different based
	 * on data padding from crypto layer.
	 */

	onwire_len = calc_data_outlen(knet_h, app_mtu_len + KNET_HEADER_ALL_SIZE) + ipproto_overhead_len;

	/*
	 * calculate the size of what we need to send to sendto(2).
	 * see also onwire.c for packet format explanation.
	 */
	data_len = app_mtu_len + knet_h->sec_hash_size + knet_h->sec_salt_size + KNET_HEADER_ALL_SIZE;

	if (knet_h->crypto_in_use_config) {
		if (data_len < (knet_h->sec_hash_size + knet_h->sec_salt_size) + 1) {
			log_debug(knet_h, KNET_SUB_PMTUD, "Aborting PMTUD process: link mtu smaller than crypto header detected (link might have been disconnected)");
			return -1;
		}

		knet_h->pmtudbuf->khp_pmtud_size = onwire_len;

		if (crypto_encrypt_and_sign(knet_h,
					    (const unsigned char *)knet_h->pmtudbuf,
					    data_len - (knet_h->sec_hash_size + knet_h->sec_salt_size),
					    knet_h->pmtudbuf_crypt,
					    (ssize_t *)&data_len) < 0) {
			log_debug(knet_h, KNET_SUB_PMTUD, "Unable to crypto pmtud packet");
			return -1;
		}

		outbuf = knet_h->pmtudbuf_crypt;
		if (pthread_mutex_lock(&knet_h->handle_stats_mutex) < 0) {
			log_err(knet_h, KNET_SUB_PMTUD, "Unable to get mutex lock");
			return -1;
		}
		knet_h->stats_extra.tx_crypt_pmtu_packets++;
		pthread_mutex_unlock(&knet_h->handle_stats_mutex);
	} else {
		knet_h->pmtudbuf->khp_pmtud_size = onwire_len;
	}

	/* link has gone down, aborting pmtud */
	if (dst_link->status.connected != 1) {
		log_debug(knet_h, KNET_SUB_PMTUD, "PMTUD detected host (%u) link (%u) has been disconnected", dst_host->host_id, dst_link->link_id);
		return -1;
	}

	if (dst_link->transport_connected != 1) {
		log_debug(knet_h, KNET_SUB_PMTUD, "PMTUD detected host (%u) link (%u) has been disconnected", dst_host->host_id, dst_link->link_id);
		return -1;
	}

	if (pthread_mutex_lock(&knet_h->pmtud_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_PMTUD, "Unable to get mutex lock");
		return -1;
	}

	if (knet_h->pmtud_abort) {
		pthread_mutex_unlock(&knet_h->pmtud_mutex);
		errno = EDEADLK;
		return -1;
	}

	savederrno = pthread_mutex_lock(&knet_h->tx_mutex);
	if (savederrno) {
		pthread_mutex_unlock(&knet_h->pmtud_mutex);
		log_err(knet_h, KNET_SUB_PMTUD, "Unable to get TX mutex lock: %s", strerror(savederrno));
		return -1;
	}

	savederrno = pthread_mutex_lock(&dst_link->link_stats_mutex);
	if (savederrno) {
		pthread_mutex_unlock(&knet_h->pmtud_mutex);
		pthread_mutex_unlock(&knet_h->tx_mutex);
		log_err(knet_h, KNET_SUB_PMTUD, "Unable to get stats mutex lock for host %u link %u: %s",
			dst_host->host_id, dst_link->link_id, strerror(savederrno));
		return -1;
	}

retry:
	if (transport_get_connection_oriented(knet_h, dst_link->transport) == TRANSPORT_PROTO_NOT_CONNECTION_ORIENTED) {
		len = sendto(dst_link->outsock, outbuf, data_len, MSG_DONTWAIT | MSG_NOSIGNAL,
			     (struct sockaddr *) &dst_link->dst_addr, sizeof(struct sockaddr_storage));
	} else {
		len = sendto(dst_link->outsock, outbuf, data_len, MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0);
	}
	savederrno = errno;

	/*
	 * we cannot hold a lock on kmtu_mutex between resetting
	 * knet_h->kernel_mtu here and below where it's used.
	 * use_kernel_mtu tells us if the knet_h->kernel_mtu was
	 * set to 0 and we can trust its value later.
	 */
	use_kernel_mtu = 0;

	if (pthread_mutex_lock(&knet_h->kmtu_mutex) == 0) {
		use_kernel_mtu = 1;
		knet_h->kernel_mtu = 0;
		pthread_mutex_unlock(&knet_h->kmtu_mutex);
	}

	kernel_mtu = 0;

	err = transport_tx_sock_error(knet_h, dst_link->transport, dst_link->outsock, len, savederrno);
	switch(err) {
		case -1: /* unrecoverable error */
			log_debug(knet_h, KNET_SUB_PMTUD, "Unable to send pmtu packet (sendto): %d %s", savederrno, strerror(savederrno));
			pthread_mutex_unlock(&knet_h->tx_mutex);
			pthread_mutex_unlock(&knet_h->pmtud_mutex);
			dst_link->status.stats.tx_pmtu_errors++;
			pthread_mutex_unlock(&dst_link->link_stats_mutex);
			return -1;
		case 0: /* ignore error and continue */
			break;
		case 1: /* retry to send those same data */
			dst_link->status.stats.tx_pmtu_retries++;
			goto retry;
			break;
	}

	pthread_mutex_unlock(&knet_h->tx_mutex);

	if (len != (ssize_t )data_len) {
		pthread_mutex_unlock(&dst_link->link_stats_mutex);
		if (savederrno == EMSGSIZE) {
			/*
			 * we cannot hold a lock on kmtu_mutex between resetting
			 * knet_h->kernel_mtu and here.
			 * use_kernel_mtu tells us if the knet_h->kernel_mtu was
			 * set to 0 previously and we can trust its value now.
			 */
			if (use_kernel_mtu) {
				use_kernel_mtu = 0;
				if (pthread_mutex_lock(&knet_h->kmtu_mutex) == 0) {
					kernel_mtu = knet_h->kernel_mtu;
					pthread_mutex_unlock(&knet_h->kmtu_mutex);
				}
			}
			if (kernel_mtu > 0) {
				dst_link->last_bad_mtu = kernel_mtu + 1;
			} else {
				dst_link->last_bad_mtu = onwire_len;
			}
		} else {
			log_debug(knet_h, KNET_SUB_PMTUD, "Unable to send pmtu packet len: %zu err: %s", onwire_len, strerror(savederrno));
		}

	} else {
		dst_link->last_sent_mtu = onwire_len;
		dst_link->last_recv_mtu = 0;
		dst_link->status.stats.tx_pmtu_packets++;
		dst_link->status.stats.tx_pmtu_bytes += data_len;
		pthread_mutex_unlock(&dst_link->link_stats_mutex);

		if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
			log_debug(knet_h, KNET_SUB_PMTUD, "Unable to get current time: %s", strerror(errno));
			pthread_mutex_unlock(&knet_h->pmtud_mutex);
			return -1;
		}

		/*
		 * non fatal, we can wait the next round to reduce the
		 * multiplier
		 */
		if (clock_gettime(CLOCK_MONOTONIC, &pmtud_crypto_start_ts) < 0) {
			log_debug(knet_h, KNET_SUB_PMTUD, "Unable to get current time: %s", strerror(errno));
			pmtud_crypto_reduce = 0;
		}

		/*
		 * set PMTUd reply timeout to match pong_timeout on a given link
		 *
		 * math: internally pong_timeout is expressed in microseconds, while
		 *       the public API exports milliseconds. So careful with the 0's here.
		 * the loop is necessary because we are grabbing the current time just above
		 * and add values to it that could overflow into seconds.
		 */ 

		if (pthread_mutex_lock(&knet_h->backoff_mutex)) {
			log_debug(knet_h, KNET_SUB_PMTUD, "Unable to get backoff_mutex");
			pthread_mutex_unlock(&knet_h->pmtud_mutex);
			return -1;
		}

		if (knet_h->crypto_in_use_config) {
			/*
			 * crypto, under pressure, is a royal PITA
			 */
			pong_timeout_adj_tmp = dst_link->pong_timeout_adj * dst_link->pmtud_crypto_timeout_multiplier;
		} else {
			pong_timeout_adj_tmp = dst_link->pong_timeout_adj;
		}

		ts.tv_sec += pong_timeout_adj_tmp / 1000000;
		ts.tv_nsec += (((pong_timeout_adj_tmp) % 1000000) * 1000);
		while (ts.tv_nsec > 1000000000) {
			ts.tv_sec += 1;
			ts.tv_nsec -= 1000000000;
		}

		pthread_mutex_unlock(&knet_h->backoff_mutex);

		knet_h->pmtud_waiting = 1;

		ret = pthread_cond_timedwait(&knet_h->pmtud_cond, &knet_h->pmtud_mutex, &ts);

		knet_h->pmtud_waiting = 0;

		if (knet_h->pmtud_abort) {
			pthread_mutex_unlock(&knet_h->pmtud_mutex);
			errno = EDEADLK;
			return -1;
		}

		/*
		 * we cannot use shutdown_in_progress in here because
		 * we already hold the read lock
		 */
		if (knet_h->fini_in_progress) {
			pthread_mutex_unlock(&knet_h->pmtud_mutex);
			log_debug(knet_h, KNET_SUB_PMTUD, "PMTUD aborted. shutdown in progress");
			return -1;
		}

		if (ret) {
			if (ret == ETIMEDOUT) {
				if ((knet_h->crypto_in_use_config) && (dst_link->pmtud_crypto_timeout_multiplier < KNET_LINK_PMTUD_CRYPTO_TIMEOUT_MULTIPLIER_MAX)) {
					dst_link->pmtud_crypto_timeout_multiplier = dst_link->pmtud_crypto_timeout_multiplier * 2;
					pmtud_crypto_reduce = 0;
					log_debug(knet_h, KNET_SUB_PMTUD,
							"Increasing PMTUd response timeout multiplier to (%u) for host %u link: %u",
							dst_link->pmtud_crypto_timeout_multiplier,
							dst_host->host_id,
							dst_link->link_id);
					pthread_mutex_unlock(&knet_h->pmtud_mutex);
					goto restart;
				}
				if (!warn_once) {
					log_warn(knet_h, KNET_SUB_PMTUD,
							"possible MTU misconfiguration detected. "
							"kernel is reporting MTU: %u bytes for "
							"host %u link %u but the other node is "
							"not acknowledging packets of this size. ",
							dst_link->last_sent_mtu,
							dst_host->host_id,
							dst_link->link_id);
					log_warn(knet_h, KNET_SUB_PMTUD,
							"This can be caused by this node interface MTU "
							"too big or a network device that does not "
							"support or has been misconfigured to manage MTU "
							"of this size, or packet loss. knet will continue "
							"to run but performances might be affected.");
					warn_once = 1;
				}
			} else {
				pthread_mutex_unlock(&knet_h->pmtud_mutex);
				if (mutex_retry_limit == 3) {
					log_debug(knet_h, KNET_SUB_PMTUD, "PMTUD aborted, unable to get mutex lock");
					return -1;
				}
				mutex_retry_limit++;
				goto restart;
			}
		}

		if ((knet_h->crypto_in_use_config) && (pmtud_crypto_reduce == 1) &&
		    (dst_link->pmtud_crypto_timeout_multiplier > KNET_LINK_PMTUD_CRYPTO_TIMEOUT_MULTIPLIER_MIN)) {
			if (!clock_gettime(CLOCK_MONOTONIC, &pmtud_crypto_stop_ts)) {
				timespec_diff(pmtud_crypto_start_ts, pmtud_crypto_stop_ts, &timediff);
				if (((pong_timeout_adj_tmp * 1000) / 2) > timediff) {
					dst_link->pmtud_crypto_timeout_multiplier = dst_link->pmtud_crypto_timeout_multiplier / 2;
					log_debug(knet_h, KNET_SUB_PMTUD,
							"Decreasing PMTUd response timeout multiplier to (%u) for host %u link: %u",
							dst_link->pmtud_crypto_timeout_multiplier,
							dst_host->host_id,
							dst_link->link_id);
				}
			} else {
				log_debug(knet_h, KNET_SUB_PMTUD, "Unable to get current time: %s", strerror(errno));
			}
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
				    ((dst_link->last_bad_mtu) && (dst_link->last_bad_mtu == (onwire_len + 1))) ||
				     (dst_link->last_bad_mtu == dst_link->last_good_mtu)) {
					found_mtu = 1;
				}
			}

			if (found_mtu) {
				/*
				 * account for IP overhead, knet headers and crypto in PMTU calculation
				 */
				dst_link->status.mtu = calc_max_data_outlen(knet_h, onwire_len - ipproto_overhead_len);
				pthread_mutex_unlock(&knet_h->pmtud_mutex);
				return 0;
			}

			dst_link->last_good_mtu = onwire_len;
		}
	}

	if (kernel_mtu) {
		onwire_len = kernel_mtu;
	} else {
		onwire_len = (dst_link->last_good_mtu + dst_link->last_bad_mtu) / 2;
	}

	pthread_mutex_unlock(&knet_h->pmtud_mutex);

	goto restart;
}

static int _handle_check_pmtud(knet_handle_t knet_h, struct knet_host *dst_host, struct knet_link *dst_link, int force_run)
{
	uint8_t saved_valid_pmtud;
	unsigned int saved_pmtud;
	struct timespec clock_now;
	unsigned long long diff_pmtud, interval;

	if (clock_gettime(CLOCK_MONOTONIC, &clock_now) != 0) {
		log_debug(knet_h, KNET_SUB_PMTUD, "Unable to get monotonic clock");
		return 0;
	}

	if (!force_run) {
		interval = knet_h->pmtud_interval * 1000000000llu; /* nanoseconds */

		timespec_diff(dst_link->pmtud_last, clock_now, &diff_pmtud);

		if (diff_pmtud < interval) {
			return dst_link->has_valid_mtu;
		}
	}

	/*
	 * status.proto_overhead should include all IP/(UDP|SCTP)/knet headers
	 *
	 * please note that it is not the same as link->proto_overhead that
	 * includes only either UDP or SCTP (at the moment) overhead.
	 */
	switch (dst_link->dst_addr.ss_family) {
		case AF_INET6:
			dst_link->status.proto_overhead = KNET_PMTUD_OVERHEAD_V6 + dst_link->proto_overhead + KNET_HEADER_ALL_SIZE + knet_h->sec_hash_size + knet_h->sec_salt_size;
			break;
		case AF_INET:
			dst_link->status.proto_overhead = KNET_PMTUD_OVERHEAD_V4 + dst_link->proto_overhead + KNET_HEADER_ALL_SIZE + knet_h->sec_hash_size + knet_h->sec_salt_size;
			break;
	}

	saved_pmtud = dst_link->status.mtu;
	saved_valid_pmtud = dst_link->has_valid_mtu;

	log_debug(knet_h, KNET_SUB_PMTUD, "Starting PMTUD for host: %u link: %u", dst_host->host_id, dst_link->link_id);

	errno = 0;
	if (_handle_check_link_pmtud(knet_h, dst_host, dst_link) < 0) {
		if (errno == EDEADLK) {
			log_debug(knet_h, KNET_SUB_PMTUD, "PMTUD for host: %u link: %u has been rescheduled", dst_host->host_id, dst_link->link_id);
			dst_link->status.mtu = saved_pmtud;
			dst_link->has_valid_mtu = saved_valid_pmtud;
			errno = EDEADLK;
			return dst_link->has_valid_mtu;
		}
		dst_link->has_valid_mtu = 0;
	} else {
		if (dst_link->status.mtu < calc_min_mtu(knet_h)) {
			log_info(knet_h, KNET_SUB_PMTUD,
				 "Invalid MTU detected for host: %u link: %u mtu: %u",
				 dst_host->host_id, dst_link->link_id, dst_link->status.mtu);
			dst_link->has_valid_mtu = 0;
		} else {
			dst_link->has_valid_mtu = 1;
		}
		if (dst_link->has_valid_mtu) {
			if ((saved_pmtud) && (saved_pmtud != dst_link->status.mtu)) {
				log_info(knet_h, KNET_SUB_PMTUD, "PMTUD link change for host: %u link: %u from %u to %u",
					 dst_host->host_id, dst_link->link_id, saved_pmtud, dst_link->status.mtu);
			}
			log_debug(knet_h, KNET_SUB_PMTUD, "PMTUD completed for host: %u link: %u current link mtu: %u",
				  dst_host->host_id, dst_link->link_id, dst_link->status.mtu);

			/*
			 * set pmtud_last, if we can, after we are done with the PMTUd process
			 * because it can take a very long time.
			 */
			dst_link->pmtud_last = clock_now;
			if (!clock_gettime(CLOCK_MONOTONIC, &clock_now)) {
				dst_link->pmtud_last = clock_now;
			}
		}
	}

	if (saved_valid_pmtud != dst_link->has_valid_mtu) {
		_host_dstcache_update_async(knet_h, dst_host);
	}

	return dst_link->has_valid_mtu;
}

void *_handle_pmtud_link_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	struct knet_host *dst_host;
	struct knet_link *dst_link;
	int link_idx;
	unsigned int have_mtu;
	unsigned int lower_mtu;
	int link_has_mtu;
	int force_run = 0;

	set_thread_status(knet_h, KNET_THREAD_PMTUD, KNET_THREAD_STARTED);

	knet_h->data_mtu = calc_min_mtu(knet_h);

	/* preparing pmtu buffer */
	knet_h->pmtudbuf->kh_version = KNET_HEADER_VERSION;
	knet_h->pmtudbuf->kh_type = KNET_HEADER_TYPE_PMTUD;
	knet_h->pmtudbuf->kh_node = htons(knet_h->host_id);

	while (!shutdown_in_progress(knet_h)) {
		usleep(knet_h->threads_timer_res);

		if (pthread_mutex_lock(&knet_h->pmtud_mutex) != 0) {
			log_debug(knet_h, KNET_SUB_PMTUD, "Unable to get mutex lock");
			continue;
		}
		knet_h->pmtud_abort = 0;
		knet_h->pmtud_running = 1;
		force_run = knet_h->pmtud_forcerun;
		knet_h->pmtud_forcerun = 0;
		pthread_mutex_unlock(&knet_h->pmtud_mutex);

		if (force_run) {
			log_debug(knet_h, KNET_SUB_PMTUD, "PMTUd request to rerun has been received");
		}

		if (pthread_rwlock_rdlock(&knet_h->global_rwlock) != 0) {
			log_debug(knet_h, KNET_SUB_PMTUD, "Unable to get read lock");
			continue;
		}

		lower_mtu = KNET_PMTUD_SIZE_V4;
		have_mtu = 0;

		for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
			for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
				dst_link = &dst_host->link[link_idx];

				if ((dst_link->status.enabled != 1) ||
				    (dst_link->status.connected != 1) ||
				    (dst_host->link[link_idx].transport == KNET_TRANSPORT_LOOPBACK) ||
				    (!dst_link->last_ping_size) ||
				    ((dst_link->dynamic == KNET_LINK_DYNIP) &&
				     (dst_link->status.dynconnected != 1)))
					continue;

				if (!knet_h->manual_mtu) {
					link_has_mtu = _handle_check_pmtud(knet_h, dst_host, dst_link, force_run);
					if (errno == EDEADLK) {
						goto out_unlock;
					}
					if (link_has_mtu) {
						have_mtu = 1;
						if (dst_link->status.mtu < lower_mtu) {
							lower_mtu = dst_link->status.mtu;
						}
					}
				} else {
					link_has_mtu = _calculate_manual_mtu(knet_h, dst_link);
					if (link_has_mtu) {
						have_mtu = 1;
						if (dst_link->status.mtu < lower_mtu) {
							lower_mtu = dst_link->status.mtu;
						}
					}
				}
			}
		}

		if (have_mtu) {
			if (knet_h->data_mtu != lower_mtu) {
				knet_h->data_mtu = lower_mtu;
				log_info(knet_h, KNET_SUB_PMTUD, "Global data MTU changed to: %u", knet_h->data_mtu);

				if (knet_h->pmtud_notify_fn) {
					knet_h->pmtud_notify_fn(knet_h->pmtud_notify_fn_private_data,
								knet_h->data_mtu);
				}
			}
		}
out_unlock:
		pthread_rwlock_unlock(&knet_h->global_rwlock);
		if (pthread_mutex_lock(&knet_h->pmtud_mutex) != 0) {
			log_debug(knet_h, KNET_SUB_PMTUD, "Unable to get mutex lock");
		} else {
			knet_h->pmtud_running = 0;
			pthread_mutex_unlock(&knet_h->pmtud_mutex);
		}
	}

	set_thread_status(knet_h, KNET_THREAD_PMTUD, KNET_THREAD_STOPPED);

	return NULL;
}
