/*
 * Copyright (C) 2012-2021 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
#include <pthread.h>

#include "compat.h"
#include "compress.h"
#include "crypto.h"
#include "host.h"
#include "links.h"
#include "links_acl.h"
#include "logging.h"
#include "transports.h"
#include "transport_common.h"
#include "threads_common.h"
#include "threads_heartbeat.h"
#include "threads_pmtud.h"
#include "threads_rx.h"
#include "netutils.h"
#include "onwire_v1.h"

/*
 * RECV
 */

/*
 *  return 1 if a > b
 *  return -1 if b > a
 *  return 0 if they are equal
 */
static inline int _timecmp(struct timespec a, struct timespec b)
{
	if (a.tv_sec != b.tv_sec) {
		if (a.tv_sec > b.tv_sec) {
			return 1;
		} else {
			return -1;
		}
	} else {
		if (a.tv_nsec > b.tv_nsec) {
			return 1;
		} else if (a.tv_nsec < b.tv_nsec) {
			return -1;
		} else {
			return 0;
		}
	}
}

/*
 * calculate use % of defrag buffers per host
 * and if % is <= knet_h->defrag_bufs_shrink_threshold for the last second, then half the size
 */

static void _shrink_defrag_buffers(knet_handle_t knet_h)
{
	struct knet_host *host;
	struct knet_host_defrag_buf *new_bufs = NULL;
	struct timespec now;
	unsigned long long time_diff; /* nanoseconds */
	uint16_t i, x, in_use_bufs;
	uint32_t sum;

	/*
	 * first run.
	 */
	if ((knet_h->defrag_bufs_last_run.tv_sec == 0) &&
	    (knet_h->defrag_bufs_last_run.tv_nsec == 0)) {
		clock_gettime(CLOCK_MONOTONIC, &knet_h->defrag_bufs_last_run);
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &now);

	timespec_diff(knet_h->defrag_bufs_last_run, now, &time_diff);

	if (time_diff < (((unsigned long long)knet_h->defrag_bufs_usage_samples_timespan * 1000000000) / knet_h->defrag_bufs_usage_samples)) {
		return;
	}

	/*
	 * record the last run
	 */
	memmove(&knet_h->defrag_bufs_last_run, &now, sizeof(struct timespec));

	/*
	 * do the real work:
	 */
	for (host = knet_h->host_head; host != NULL; host = host->next) {

		/*
		 * Update buffer usage stats. We do this for all nodes.
		 */
		in_use_bufs = 0;

		for (i = 0; i < host->allocated_defrag_bufs; i++) {
			if (host->defrag_bufs[i].in_use) {
				in_use_bufs++;
			}
		}

		/*
		 * record only %
		 */
		host->in_use_defrag_buffers[host->in_use_defrag_buffers_index] = (in_use_bufs * 100 / host->allocated_defrag_bufs);
		host->in_use_defrag_buffers_index++;

		/*
		 * make sure to stay within buffer
		 */
		if (host->in_use_defrag_buffers_index == knet_h->defrag_bufs_usage_samples) {
			host->in_use_defrag_buffers_index = 0;
		}

		/*
		 * only allow shrinking if we have enough samples
		 */
		if (host->in_use_defrag_buffers_samples < knet_h->defrag_bufs_usage_samples) {
			host->in_use_defrag_buffers_samples++;
			continue;
		}

		/*
		 * only allow shrinking if in use bufs are <= knet_h->defrag_bufs_shrink_threshold%
		 */
		if (knet_h->defrag_bufs_reclaim_policy == RECLAIM_POLICY_AVERAGE) {
			sum = 0;
			for (i = 0; i < knet_h->defrag_bufs_usage_samples; i++) {
				sum += host->in_use_defrag_buffers[i];
			}
			sum = sum / knet_h->defrag_bufs_usage_samples;

			if (sum > knet_h->defrag_bufs_shrink_threshold) {
				continue;
			}
		} else {
			sum = 0;
			for (i = 0; i < knet_h->defrag_bufs_usage_samples; i++) {
				if (host->in_use_defrag_buffers[i] > knet_h->defrag_bufs_shrink_threshold) {
					sum = 1;
				}
			}

			if (sum) {
				continue;
			}
		}

		/*
		 * only allow shrinking if allocated bufs > min_defrag_bufs
		 */
		if (host->allocated_defrag_bufs == knet_h->defrag_bufs_min) {
			continue;
		}

		/*
		 * compat all the in_use buffers at the beginning.
		 * we the checks above, we are 100% sure they fit
		 */
		x = 0;
		for (i = 0; i < host->allocated_defrag_bufs; i++) {
			if (host->defrag_bufs[i].in_use) {
				memmove(&host->defrag_bufs[x], &host->defrag_bufs[i], sizeof(struct knet_host_defrag_buf));
				x++;
			}
		}

		/*
		 * memory allocation is not critical. it just means the system is under
		 * memory pressure and we will need to wait our turn to free memory... how odd :)
		 */
		new_bufs = realloc(host->defrag_bufs, sizeof(struct knet_host_defrag_buf) * (host->allocated_defrag_bufs / 2));
		if (!new_bufs) {
			log_err(knet_h, KNET_SUB_RX, "Unable to decrease defrag buffers for host %u: %s",
				host->host_id, strerror(errno));
			continue;
		}

		host->defrag_bufs = new_bufs;
		host->allocated_defrag_bufs = host->allocated_defrag_bufs / 2;

		/*
		 * clear buffer use stats. Old ones are no good for new one
		 */
		_clear_defrag_bufs_stats(host);

		log_debug(knet_h, KNET_SUB_RX, "Defrag buffers for host %u decreased from %u to: %u",
			  host->host_id, host->allocated_defrag_bufs * 2, host->allocated_defrag_bufs);
	}
}

/*
 * check if we can double the defrag buffers.
 *
 * return 0 if we cannot reallocate
 * return 1 if we have more buffers
 */

static int _realloc_defrag_buffers(knet_handle_t knet_h, struct knet_host *src_host)
{
	struct knet_host_defrag_buf *new_bufs = NULL;
	int i;

	/*
	 * max_defrag_bufs is a power of 2
	 * allocated_defrag_bufs doubles on each iteration.
	 * Sooner or later (and hopefully never) allocated with be == to max.
	 */
	if (src_host->allocated_defrag_bufs < knet_h->defrag_bufs_max) {
		new_bufs = realloc(src_host->defrag_bufs,
				   src_host->allocated_defrag_bufs * 2 * sizeof(struct knet_host_defrag_buf));
		if (!new_bufs) {
			log_err(knet_h, KNET_SUB_RX, "Unable to increase defrag buffers for host %u: %s",
				src_host->host_id, strerror(errno));
			return 0;
		}

		/*
		 * keep the math simple here between arrays, pointers and what not.
		 * Init each buffer individually.
		 */
		for (i = src_host->allocated_defrag_bufs; i < src_host->allocated_defrag_bufs * 2; i++) {
			memset(&new_bufs[i], 0, sizeof(struct knet_host_defrag_buf));
		}

		src_host->allocated_defrag_bufs = src_host->allocated_defrag_bufs * 2;

		src_host->defrag_bufs = new_bufs;

		/*
		 * clear buffer use stats. Old ones are no good for new one
		 */
		_clear_defrag_bufs_stats(src_host);

		log_debug(knet_h, KNET_SUB_RX, "Defrag buffers for host %u increased from %u to: %u",
			  src_host->host_id, src_host->allocated_defrag_bufs / 2, src_host->allocated_defrag_bufs);

		return 1;
	}

	return 0;
}

/*
 * this functions needs to return an index
 * to a knet_host_defrag_buf. (-1 on errors)
 */

static int _find_pckt_defrag_buf(knet_handle_t knet_h, struct knet_host *src_host, seq_num_t seq_num)
{
	int i, oldest;
	uint16_t cur_allocated_defrag_bufs = src_host->allocated_defrag_bufs;

	/*
	 * check if there is a buffer already in use handling the same seq_num
	 */

	for (i = 0; i < src_host->allocated_defrag_bufs; i++) {
		if (src_host->defrag_bufs[i].in_use) {
			if (src_host->defrag_bufs[i].pckt_seq == seq_num) {
				return i;
			}
		}
	}

	/*
	 * If there is no buffer that's handling the current seq_num
	 * either it's new or it's been reclaimed already.
	 * check if it's been reclaimed/seen before using the defrag circular
	 * buffer. If the pckt has been seen before, the buffer expired (ETIME)
	 * and there is no point to try to defrag it again.
	 */

	if (!_seq_num_lookup(knet_h, src_host, seq_num, 1, 0)) {
		errno = ETIME;
		return -1;
	}

	/*
	 * register the pckt as seen
	 */

	_seq_num_set(src_host, seq_num, 1);

	/*
	 * see if there is a free buffer
	 */

	for (i = 0; i < src_host->allocated_defrag_bufs; i++) {
		if (!src_host->defrag_bufs[i].in_use) {
			return i;
		}
	}

	/*
	 * check if we can increase num of buffers
	 */

	if (_realloc_defrag_buffers(knet_h, src_host)) {
		return cur_allocated_defrag_bufs + 1;
	}

	/*
	 * at this point, there are no free buffers, the pckt is new
	 * and we need to reclaim a buffer, and we will take the one
	 * with the oldest timestamp. It's as good as any.
	 */

	oldest = 0;

	for (i = 0; i < src_host->allocated_defrag_bufs; i++) {
		if (_timecmp(src_host->defrag_bufs[i].last_update, src_host->defrag_bufs[oldest].last_update) < 0) {
			oldest = i;
		}
	}
	src_host->defrag_bufs[oldest].in_use = 0;

	return oldest;
}

static int _pckt_defrag(knet_handle_t knet_h, struct knet_host *src_host, seq_num_t seq_num, unsigned char *data, ssize_t *len, uint8_t frags, uint8_t frag_seq)
{
	struct knet_host_defrag_buf *defrag_buf;
	int defrag_buf_idx;

	defrag_buf_idx = _find_pckt_defrag_buf(knet_h, src_host, seq_num);
	if (defrag_buf_idx < 0) {
		return 1;
	}

	defrag_buf = &src_host->defrag_bufs[defrag_buf_idx];

	/*
	 * if the buf is not is use, then make sure it's clean
	 */
	if (!defrag_buf->in_use) {
		memset(defrag_buf, 0, sizeof(struct knet_host_defrag_buf));
		defrag_buf->in_use = 1;
		defrag_buf->pckt_seq = seq_num;
	}

	/*
	 * update timestamp on the buffer
	 */
	clock_gettime(CLOCK_MONOTONIC, &defrag_buf->last_update);

	/*
	 * check if we already received this fragment
	 */
	if (defrag_buf->frag_map[frag_seq]) {
		/*
		 * if we have received this fragment and we didn't clear the buffer
		 * it means that we don't have all fragments yet
		 */
		return 1;
	}

	/*
	 *  we need to handle the last packet with gloves due to its different size
	 */

	if (frag_seq == frags) {
		defrag_buf->last_frag_size = *len;

		/*
		 * in the event when the last packet arrives first,
		 * we still don't know the offset vs the other fragments (based on MTU),
		 * so we store the fragment at the end of the buffer where it's safe
		 * and take a copy of the len so that we can restore its offset later.
		 * remember we can't use the local MTU for this calculation because pMTU
		 * can be asymettric between the same hosts.
		 */
		if (!defrag_buf->frag_size) {
			defrag_buf->last_first = 1;
			memmove(defrag_buf->buf + (KNET_MAX_PACKET_SIZE - *len),
			       data,
			       *len);
		}
	} else {
		defrag_buf->frag_size = *len;
	}

	if (defrag_buf->frag_size) {
		memmove(defrag_buf->buf + ((frag_seq - 1) * defrag_buf->frag_size),
			data, *len);
	}

	defrag_buf->frag_recv++;
	defrag_buf->frag_map[frag_seq] = 1;

	/*
	 * check if we received all the fragments
	 */
	if (defrag_buf->frag_recv == frags) {
		/*
		 * special case the last pckt
		 */

		if (defrag_buf->last_first) {
			memmove(defrag_buf->buf + ((frags - 1) * defrag_buf->frag_size),
			        defrag_buf->buf + (KNET_MAX_PACKET_SIZE - defrag_buf->last_frag_size),
				defrag_buf->last_frag_size);
		}

		/*
		 * recalculate packet lenght
		 */

		*len = ((frags - 1) * defrag_buf->frag_size) + defrag_buf->last_frag_size;

		/*
		 * copy the pckt back in the user data
		 */
		memmove(data, defrag_buf->buf, *len);

		/*
		 * free this buffer
		 */
		defrag_buf->in_use = 0;
		return 0;
	}

	return 1;
}

static int _handle_data_stats(knet_handle_t knet_h, struct knet_link *src_link, ssize_t len, uint64_t decrypt_time)
{
	int stats_err;

	/* data stats at the top for consistency with TX */
	src_link->status.stats.rx_data_packets++;
	src_link->status.stats.rx_data_bytes += len;

	if (decrypt_time) {
		stats_err = pthread_mutex_lock(&knet_h->handle_stats_mutex);
		if (stats_err < 0) {
			log_err(knet_h, KNET_SUB_RX, "Unable to get mutex lock: %s", strerror(stats_err));
			return -1;
		}
		/* Only update the crypto overhead for data packets. Mainly to be
		   consistent with TX */
		if (decrypt_time < knet_h->stats.rx_crypt_time_min) {
			knet_h->stats.rx_crypt_time_min = decrypt_time;
		}
		if (decrypt_time > knet_h->stats.rx_crypt_time_max) {
			knet_h->stats.rx_crypt_time_max = decrypt_time;
		}
		knet_h->stats.rx_crypt_time_ave =
			(knet_h->stats.rx_crypt_time_ave * knet_h->stats.rx_crypt_packets +
			 decrypt_time) / (knet_h->stats.rx_crypt_packets+1);
		knet_h->stats.rx_crypt_packets++;
		pthread_mutex_unlock(&knet_h->handle_stats_mutex);
	}
	return 0;
}

static int _decompress_data(knet_handle_t knet_h, uint8_t decompress_type, unsigned char *data, ssize_t *len, ssize_t header_size)
{
	int err = 0, stats_err = 0;

	if (decompress_type) {
		ssize_t decmp_outlen = KNET_DATABUFSIZE_COMPRESS;
		struct timespec start_time;
		struct timespec end_time;
		uint64_t decompress_time;

		clock_gettime(CLOCK_MONOTONIC, &start_time);
		err = decompress(knet_h, decompress_type,
				 data,
				 *len - header_size,
				 knet_h->recv_from_links_buf_decompress,
				 &decmp_outlen);

		clock_gettime(CLOCK_MONOTONIC, &end_time);
		timespec_diff(start_time, end_time, &decompress_time);

		stats_err = pthread_mutex_lock(&knet_h->handle_stats_mutex);
		if (stats_err < 0) {
			log_err(knet_h, KNET_SUB_RX, "Unable to get mutex lock: %s", strerror(stats_err));
			return -1;
		}

		if (!err) {
			/* Collect stats */
			if (decompress_time < knet_h->stats.rx_compress_time_min) {
				knet_h->stats.rx_compress_time_min = decompress_time;
			}
			if (decompress_time > knet_h->stats.rx_compress_time_max) {
				knet_h->stats.rx_compress_time_max = decompress_time;
			}
			knet_h->stats.rx_compress_time_ave =
				(knet_h->stats.rx_compress_time_ave * knet_h->stats.rx_compressed_packets +
				 decompress_time) / (knet_h->stats.rx_compressed_packets+1);

			knet_h->stats.rx_compressed_packets++;
			knet_h->stats.rx_compressed_original_bytes += decmp_outlen;
			knet_h->stats.rx_compressed_size_bytes += *len - KNET_HEADER_SIZE;

			memmove(data, knet_h->recv_from_links_buf_decompress, decmp_outlen);
			*len = decmp_outlen + header_size;
		} else {
			knet_h->stats.rx_failed_to_decompress++;
			pthread_mutex_unlock(&knet_h->handle_stats_mutex);
			log_err(knet_h, KNET_SUB_COMPRESS, "Unable to decompress packet (%d): %s",
				err, strerror(errno));
			return -1;
		}
		pthread_mutex_unlock(&knet_h->handle_stats_mutex);
	}
	return 0;
}

static int _check_destination(knet_handle_t knet_h, struct knet_header *inbuf, unsigned char *data, ssize_t len, ssize_t header_size, int8_t *channel)
{
	knet_node_id_t dst_host_ids[KNET_MAX_HOST];
	size_t dst_host_ids_entries = 0;
	int bcast = 1;
	size_t host_idx;
	int found = 0;

	if (knet_h->dst_host_filter_fn) {
		bcast = knet_h->dst_host_filter_fn(
				knet_h->dst_host_filter_fn_private_data,
				data,
				len - header_size,
				KNET_NOTIFY_RX,
				knet_h->host_id,
				inbuf->kh_node,
				channel,
				dst_host_ids,
				&dst_host_ids_entries);
		if (bcast < 0) {
			log_debug(knet_h, KNET_SUB_RX, "Error from dst_host_filter_fn: %d", bcast);
			return -1;
		}

		if ((!bcast) && (!dst_host_ids_entries)) {
			log_debug(knet_h, KNET_SUB_RX, "Message is unicast but no dst_host_ids_entries");
			return -1;
		}

		/* check if we are dst for this packet */
		if (!bcast) {
			if (dst_host_ids_entries > KNET_MAX_HOST) {
				log_debug(knet_h, KNET_SUB_RX, "dst_host_filter_fn returned too many destinations");
				return -1;
			}
			for (host_idx = 0; host_idx < dst_host_ids_entries; host_idx++) {
				if (dst_host_ids[host_idx] == knet_h->host_id) {
					found = 1;
					break;
				}
			}
			if (!found) {
				log_debug(knet_h, KNET_SUB_RX, "Packet is not for us");
				return -1;
			}
		}
	}
	return 0;
}

static int _deliver_data(knet_handle_t knet_h, unsigned char *data, ssize_t len, ssize_t header_size, int8_t channel)
{
	struct iovec iov_out[1];
	ssize_t	outlen = 0;

	memset(iov_out, 0, sizeof(iov_out));

retry:
	iov_out[0].iov_base = (void *) data + outlen;
	iov_out[0].iov_len = len - (outlen + header_size);

	outlen = writev(knet_h->sockfd[channel].sockfd[knet_h->sockfd[channel].is_created], iov_out, 1);
	if ((outlen > 0) && (outlen < (ssize_t)iov_out[0].iov_len)) {
		log_debug(knet_h, KNET_SUB_RX,
			  "Unable to send all data to the application in one go. Expected: %zu Sent: %zd\n",
			  iov_out[0].iov_len, outlen);
		goto retry;
	}

	if (outlen <= 0) {
		knet_h->sock_notify_fn(knet_h->sock_notify_fn_private_data,
				       knet_h->sockfd[channel].sockfd[0],
				       channel,
				       KNET_NOTIFY_RX,
				       outlen,
				       errno);
		return -1;
	}

	if ((size_t)outlen != iov_out[0].iov_len) {
		return -1;
	}

	return 0;
}

static void _process_data(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link, struct knet_header *inbuf, ssize_t len, uint64_t decrypt_time)
{
	int8_t channel;
       	uint8_t decompress_type = 0;
	ssize_t header_size;
	seq_num_t seq_num;
	uint8_t frags, frag_seq;
	unsigned char *data;

	if (_handle_data_stats(knet_h, src_link, len, decrypt_time) < 0) {
		return;
	}

	/*
	 * register host is sending data. Required to determine if we need
	 * to reset circular buffers. (see onwire_v1.c)
	 */
	src_host->got_data = 1;

	if (knet_h->onwire_ver_remap) {
		get_data_header_info_v1(knet_h, inbuf, &header_size, &channel, &seq_num, &decompress_type, &frags, &frag_seq);
		data = get_data_v1(knet_h, inbuf);
	} else {
		switch (inbuf->kh_version) {
			case 1:
				get_data_header_info_v1(knet_h, inbuf, &header_size, &channel, &seq_num, &decompress_type, &frags, &frag_seq);
				data = get_data_v1(knet_h, inbuf);
				break;
			default:
				log_warn(knet_h, KNET_SUB_RX, "processing data onwire version %u not supported", inbuf->kh_version);
				return;
				break;
		}
	}

	if (!_seq_num_lookup(knet_h, src_host, seq_num, 0, 0)) {
		if (src_host->link_handler_policy != KNET_LINK_POLICY_ACTIVE) {
			log_debug(knet_h, KNET_SUB_RX, "Packet has already been delivered");
		}
		return;
	}

	if (frags > 1) {
		/*
		 * len as received from the socket also includes extra stuff
		 * that the defrag code doesn't care about. So strip it
		 * here and readd only for repadding once we are done
		 * defragging
		 *
		 * the defrag code assumes that data packets have all the same size
		 * except the last one that might be smaller.
		 *
		 */
		len = len - header_size;
		if (_pckt_defrag(knet_h, src_host, seq_num, data, &len, frags, frag_seq)) {
			return;
		}
		len = len + header_size;
	}

	if (_decompress_data(knet_h, decompress_type, data, &len, header_size) < 0) {
		return;
	}

	if (!src_host->status.reachable) {
		log_debug(knet_h, KNET_SUB_RX, "Source host %u not reachable yet. Discarding packet.", src_host->host_id);
		return;
	}

	if (knet_h->enabled != 1) /* data forward is disabled */
		return;

	if (_check_destination(knet_h, inbuf, data, len, header_size, &channel) < 0) {
		return;
	}

	if (!knet_h->sockfd[channel].in_use) {
		log_debug(knet_h, KNET_SUB_RX,
			  "received packet for channel %d but there is no local sock connected",
			  channel);
		return;
	}

#ifdef ONWIRE_V1_EXTRA_DEBUG
	if (inbuf->khp_data_v1_checksum != compute_chksum(data, len - header_size)) {
		log_err(knet_h, KNET_SUB_RX, "Received incorrect data checksum after reassembly from host: %u seq: %u", src_host->host_id, seq_num);
		/*
		 * give a chance to the log threads to pick up the message
		 */
		sleep(1);
		abort();
	}
#endif

	if (_deliver_data(knet_h, data, len, header_size, channel) < 0) {
		return;
	}

	_seq_num_set(src_host, seq_num, 0);
}

static struct knet_header *_decrypt_packet(knet_handle_t knet_h, struct knet_header *inbuf, ssize_t *len, uint64_t *decrypt_time)
{
	int try_decrypt = 0;
	int i = 0;
	struct timespec start_time;
	struct timespec end_time;
	ssize_t outlen;

	for (i = 1; i <= KNET_MAX_CRYPTO_INSTANCES; i++) {
		if (knet_h->crypto_instance[i]) {
			try_decrypt = 1;
			break;
		}
	}

	if ((!try_decrypt) && (knet_h->crypto_only == KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC)) {
		log_debug(knet_h, KNET_SUB_RX, "RX thread configured to accept only crypto packets, but no crypto configs are configured!");
		return NULL;
	}

	if (try_decrypt) {
		clock_gettime(CLOCK_MONOTONIC, &start_time);
		if (crypto_authenticate_and_decrypt(knet_h,
						    (unsigned char *)inbuf,
						    *len,
						    knet_h->recv_from_links_buf_decrypt,
						    &outlen) < 0) {
			log_debug(knet_h, KNET_SUB_RX, "Unable to decrypt/auth packet");
			if (knet_h->crypto_only == KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC) {
				return NULL;
			}
			log_debug(knet_h, KNET_SUB_RX, "Attempting to process packet as clear data");
		} else {
			clock_gettime(CLOCK_MONOTONIC, &end_time);
			timespec_diff(start_time, end_time, decrypt_time);

			*len = outlen;
			inbuf = (struct knet_header *)knet_h->recv_from_links_buf_decrypt;
		}
	}
	return inbuf;
}

static int _packet_checks(knet_handle_t knet_h, struct knet_header *inbuf, ssize_t len)
{
#ifdef ONWIRE_V1_EXTRA_DEBUG
	uint32_t rx_packet_checksum, expected_packet_checksum;
#endif

	if (len < (ssize_t)(KNET_HEADER_SIZE + 1)) {
		log_debug(knet_h, KNET_SUB_RX, "Packet is too short: %ld", (long)len);
		return -1;
	}

#ifdef ONWIRE_V1_EXTRA_DEBUG
	inbuf->kh_node = htons(inbuf->kh_node);
	rx_packet_checksum = inbuf->kh_checksum;
	inbuf->kh_checksum = 0;
	expected_packet_checksum = compute_chksum((const unsigned char *)inbuf, len);
	if (rx_packet_checksum != expected_packet_checksum) {
		log_err(knet_h, KNET_SUB_RX, "Received packet with incorrect checksum. Received: %u Expected: %u", rx_packet_checksum, expected_packet_checksum);
		/*
		 * give a chance to the log threads to pick up the message
		 */
		sleep(1);
		abort();
	}
	inbuf->kh_node = ntohs(inbuf->kh_node);
#endif

	/*
	 * old versions of knet did not advertise max_ver and max_ver is set to 0.
	 */
	if (!inbuf->kh_max_ver) {
		inbuf->kh_max_ver = 1;
	}

	/*
	 * if the node joining max version is lower than the min version
	 * then we reject the node
	 */
	if (inbuf->kh_max_ver < knet_h->onwire_min_ver) {
		log_warn(knet_h, KNET_SUB_RX,
			 "Received packet version %u from node %u, lower than currently minimal supported onwire version. Rejecting.", inbuf->kh_version, inbuf->kh_node);
		return -1;
	}

	/*
	 * if the node joining with version higher than our max version
	 * then we reject the node
	 */
	if (inbuf->kh_version > knet_h->onwire_max_ver) {
		log_warn(knet_h, KNET_SUB_RX,
			 "Received packet version %u from node %u, higher than currently maximum supported onwire version. Rejecting.", inbuf->kh_version, inbuf->kh_node);
		return -1;
	}

	/*
	 * if the node joining with version lower than the current in use version
	 * then we reject the node
	 *
	 * NOTE: should we make this configurable and support downgrades?
	 */
	if ((!knet_h->onwire_force_ver) &&
	    (inbuf->kh_version < knet_h->onwire_ver) &&
	    (inbuf->kh_max_ver > inbuf->kh_version)) {
		log_warn(knet_h, KNET_SUB_RX,
			 "Received packet version %u from node %u, lower than currently in use onwire version. Rejecting.", inbuf->kh_version, inbuf->kh_node);
		return -1;
	}
	return 0;
}

static void _handle_dynip(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link, int sockfd, const struct knet_mmsghdr *msg)
{
	if (src_link->dynamic == KNET_LINK_DYNIP) {
		if (cmpaddr(&src_link->dst_addr, msg->msg_hdr.msg_name) != 0) {
			log_debug(knet_h, KNET_SUB_RX, "host: %u link: %u appears to have changed ip address",
				  src_host->host_id, src_link->link_id);
			memmove(&src_link->dst_addr, msg->msg_hdr.msg_name, sizeof(struct sockaddr_storage));
			if (knet_addrtostr(&src_link->dst_addr, sockaddr_len(&src_link->dst_addr),
					src_link->status.dst_ipaddr, KNET_MAX_HOST_LEN,
					src_link->status.dst_port, KNET_MAX_PORT_LEN) != 0) {
				log_debug(knet_h, KNET_SUB_RX, "Unable to resolve ???");
				snprintf(src_link->status.dst_ipaddr, KNET_MAX_HOST_LEN - 1, "Unknown!!!");
				snprintf(src_link->status.dst_port, KNET_MAX_PORT_LEN - 1, "??");
			} else {
				log_info(knet_h, KNET_SUB_RX,
					 "host: %u link: %u new connection established from: %s:%s",
					 src_host->host_id, src_link->link_id,
					 src_link->status.dst_ipaddr, src_link->status.dst_port);
			}
		}
		/*
		 * transport has already accepted the connection here
		 * otherwise we would not be receiving packets
		 */
		transport_link_dyn_connect(knet_h, sockfd, src_link);
	}
}

/*
 * processing incoming packets vs access lists
 */
static int _check_rx_acl(knet_handle_t knet_h, struct knet_link *src_link, const struct knet_mmsghdr *msg)
{
	if (knet_h->use_access_lists) {
		if (!check_validate(knet_h, src_link, msg->msg_hdr.msg_name)) {
			char src_ipaddr[KNET_MAX_HOST_LEN];
			char src_port[KNET_MAX_PORT_LEN];

			memset(src_ipaddr, 0, KNET_MAX_HOST_LEN);
			memset(src_port, 0, KNET_MAX_PORT_LEN);
			if (knet_addrtostr(msg->msg_hdr.msg_name, sockaddr_len(msg->msg_hdr.msg_name),
					   src_ipaddr, KNET_MAX_HOST_LEN,
					   src_port, KNET_MAX_PORT_LEN) < 0) {

				log_warn(knet_h, KNET_SUB_RX, "Packet rejected: unable to resolve host/port");
			} else {
				log_warn(knet_h, KNET_SUB_RX, "Packet rejected from %s:%s", src_ipaddr, src_port);
			}
			return 0;
		}
	}
	return 1;
}

static void _parse_recv_from_links(knet_handle_t knet_h, int sockfd, const struct knet_mmsghdr *msg)
{
	int savederrno = 0, stats_err = 0;
	struct knet_host *src_host;
	struct knet_link *src_link;
	uint64_t decrypt_time = 0;
	struct knet_header *inbuf = msg->msg_hdr.msg_iov->iov_base;
	ssize_t len = msg->msg_len;
	int i, found_link = 0;

	inbuf = _decrypt_packet(knet_h, inbuf, &len, &decrypt_time);
	if (!inbuf) {
		char src_ipaddr[KNET_MAX_HOST_LEN];
		char src_port[KNET_MAX_PORT_LEN];

		memset(src_ipaddr, 0, KNET_MAX_HOST_LEN);
		memset(src_port, 0, KNET_MAX_PORT_LEN);
		if (knet_addrtostr(msg->msg_hdr.msg_name, sockaddr_len(msg->msg_hdr.msg_name),
				   src_ipaddr, KNET_MAX_HOST_LEN,
				   src_port, KNET_MAX_PORT_LEN) < 0) {

			log_err(knet_h, KNET_SUB_RX, "Unable to decrypt packet from unknown host/port (size %zu)!", len);
		} else {
			log_err(knet_h, KNET_SUB_RX, "Unable to decrypt packet from %s:%s (size %zu)!", src_ipaddr, src_port, len);
		}
		return;
	}

	inbuf->kh_node = ntohs(inbuf->kh_node);

	if (_packet_checks(knet_h, inbuf, len) < 0) {
		if (knet_h->rx_odd_packets < KNET_RX_ODD_PACKETS_THRESHOLD) {
			knet_h->rx_odd_packets++;
		} else {
			log_warn(knet_h, KNET_SUB_RX, "This node has received more than %u packets that have failed basic sanity checks", KNET_RX_ODD_PACKETS_THRESHOLD);
			log_warn(knet_h, KNET_SUB_RX, "It is highly recommended to check if all nodes are using the same crypto configuration");
			knet_h->rx_odd_packets = 0;
		}
		return;
	}

	/*
	 * determine source host
	 */
	src_host = knet_h->host_index[inbuf->kh_node];
	if (src_host == NULL) {  /* host not found */
		log_debug(knet_h, KNET_SUB_RX, "Unable to find source host for this packet");
		return;
	}

	/*
	 * deteremine source link
	 */
	if (inbuf->kh_type == KNET_HEADER_TYPE_PING) {
		_handle_onwire_version(knet_h, src_host, inbuf);
		if (knet_h->onwire_ver_remap) {
			src_link = get_link_from_pong_v1(knet_h, src_host, inbuf);
		} else {
			switch (inbuf->kh_version) {
				case 1:
					src_link = get_link_from_pong_v1(knet_h, src_host, inbuf);
					break;
				default:
					log_warn(knet_h, KNET_SUB_RX, "Parsing ping onwire version %u not supported", inbuf->kh_version);
					return;
					break;
			}
		}
		if (!_check_rx_acl(knet_h, src_link, msg)) {
			return;
		}
		_handle_dynip(knet_h, src_host, src_link, sockfd, msg);
	} else { /* all other packets */
		for (i = 0; i < KNET_MAX_LINK; i++) {
			src_link = &src_host->link[i];
			if (cmpaddr(&src_link->dst_addr, msg->msg_hdr.msg_name) == 0) {
				found_link = 1;
				break;
			}
		}
		if (found_link) {
			/*
			 * this check is currently redundant.. Keep it here for now
			 */
			if (!_check_rx_acl(knet_h, src_link, msg)) {
				return;
			}
		} else {
			log_debug(knet_h, KNET_SUB_RX, "Unable to determine source link for data packet. Discarding packet.");
			return;
		}
	}

	stats_err = pthread_mutex_lock(&src_link->link_stats_mutex);
	if (stats_err) {
		log_err(knet_h, KNET_SUB_RX, "Unable to get stats mutex lock for host %u link %u: %s",
			src_host->host_id, src_link->link_id, strerror(savederrno));
		return;
	}

	switch (inbuf->kh_type) {
		case KNET_HEADER_TYPE_DATA:
			_process_data(knet_h, src_host, src_link, inbuf, len, decrypt_time);
			break;
		case KNET_HEADER_TYPE_PING:
			process_ping(knet_h, src_host, src_link, inbuf, len);
			break;
		case KNET_HEADER_TYPE_PONG:
			process_pong(knet_h, src_host, src_link, inbuf, len);
			break;
		case KNET_HEADER_TYPE_PMTUD:
			src_link->status.stats.rx_pmtu_packets++;
			src_link->status.stats.rx_pmtu_bytes += len;
			/* Unlock so we don't deadlock with tx_mutex */
			pthread_mutex_unlock(&src_link->link_stats_mutex);
			process_pmtud(knet_h, src_link, inbuf);
			return; /* Don't need to unlock link_stats_mutex */
			break;
		case KNET_HEADER_TYPE_PMTUD_REPLY:
			src_link->status.stats.rx_pmtu_packets++;
			src_link->status.stats.rx_pmtu_bytes += len;
			/* pmtud_mutex can't be acquired while we hold a link_stats_mutex (ordering) */
			pthread_mutex_unlock(&src_link->link_stats_mutex);
			process_pmtud_reply(knet_h, src_link, inbuf);
			return;
			break;
		default:
			pthread_mutex_unlock(&src_link->link_stats_mutex);
			return;
			break;
	}
	pthread_mutex_unlock(&src_link->link_stats_mutex);
}

static void _handle_recv_from_links(knet_handle_t knet_h, int sockfd, struct knet_mmsghdr *msg)
{
	int err, savederrno;
	int i, msg_recv, transport;

	if (pthread_rwlock_rdlock(&knet_h->global_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_RX, "Unable to get global read lock");
		return;
	}

	if (_is_valid_fd(knet_h, sockfd) < 1) {
		/*
		 * this is normal if a fd got an event and before we grab the read lock
		 * and the link is removed by another thread
		 */
		goto exit_unlock;
	}

	transport = knet_h->knet_transport_fd_tracker[sockfd].transport;

	/*
	 * reset msg_namelen to buffer size because after recvmmsg
	 * each msg_namelen will contain sizeof sockaddr_in or sockaddr_in6
	 */

	for (i = 0; i < PCKT_RX_BUFS; i++) {
		msg[i].msg_hdr.msg_namelen = knet_h->knet_transport_fd_tracker[sockfd].sockaddr_len;
	}

	msg_recv = _recvmmsg(sockfd, &msg[0], PCKT_RX_BUFS, MSG_DONTWAIT | MSG_NOSIGNAL);
	savederrno = errno;

	/*
	 * WARNING: man page for recvmmsg is wrong. Kernel implementation here:
	 * recvmmsg can return:
	 * -1 on error
	 *  0 if the previous run of recvmmsg recorded an error on the socket
	 *  N number of messages (see exception below).
	 *
	 * If there is an error from recvmsg after receiving a frame or more, the recvmmsg
	 * loop is interrupted, error recorded in the socket (getsockopt(SO_ERROR) and
	 * it will be visibile in the next run.
	 *
	 * Need to be careful how we handle errors at this stage.
	 *
	 * error messages need to be handled on a per transport/protocol base
	 * at this point we have different layers of error handling
	 * - msg_recv < 0 -> error from this run
	 *   msg_recv = 0 -> error from previous run and error on socket needs to be cleared
	 * - per-transport message data
	 *   example: msg[i].msg_hdr.msg_flags & MSG_NOTIFICATION or msg_len for SCTP == EOF,
	 *            but for UDP it is perfectly legal to receive a 0 bytes message.. go figure
	 * - NOTE: on SCTP MSG_NOTIFICATION we get msg_recv == PCKT_FRAG_MAX messages and no
	 *         errno set. That means the error api needs to be able to abort the loop below.
	 */

	if (msg_recv <= 0) {
		transport_rx_sock_error(knet_h, transport, sockfd, msg_recv, savederrno);
		goto exit_unlock;
	}

	for (i = 0; i < msg_recv; i++) {
		err = transport_rx_is_data(knet_h, transport, sockfd, &msg[i]);

		/*
		 * TODO: make this section silent once we are confident
		 *       all protocols packet handlers are good
		 */

		switch(err) {
			case KNET_TRANSPORT_RX_ISDATA_ERROR: /* on error */
				log_debug(knet_h, KNET_SUB_RX, "Transport reported error parsing packet");
				goto exit_unlock;
				break;
			case KNET_TRANSPORT_RX_NOT_DATA_CONTINUE: /* packet is not data and we should continue the packet process loop */
				log_debug(knet_h, KNET_SUB_RX, "Transport reported no data, continue");
				break;
			case KNET_TRANSPORT_RX_NOT_DATA_STOP: /* packet is not data and we should STOP the packet process loop */
				log_debug(knet_h, KNET_SUB_RX, "Transport reported no data, stop");
				goto exit_unlock;
				break;
			case KNET_TRANSPORT_RX_IS_DATA: /* packet is data and should be parsed as such */
				_parse_recv_from_links(knet_h, sockfd, &msg[i]);
				break;
			case KNET_TRANSPORT_RX_OOB_DATA_CONTINUE:
				log_debug(knet_h, KNET_SUB_RX, "Transport is processing sock OOB data, continue");
				break;
			case KNET_TRANSPORT_RX_OOB_DATA_STOP:
				log_debug(knet_h, KNET_SUB_RX, "Transport has completed processing sock OOB data, stop");
				goto exit_unlock;
				break;
		}
	}

exit_unlock:
	_shrink_defrag_buffers(knet_h);
	pthread_rwlock_unlock(&knet_h->global_rwlock);
}

void *_handle_recv_from_links_thread(void *data)
{
	int i, nev;
	knet_handle_t knet_h = (knet_handle_t) data;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];
	struct sockaddr_storage address[PCKT_RX_BUFS];
	struct knet_mmsghdr msg[PCKT_RX_BUFS];
	struct iovec iov_in[PCKT_RX_BUFS];

	set_thread_status(knet_h, KNET_THREAD_RX, KNET_THREAD_STARTED);

	memset(&msg, 0, sizeof(msg));
	memset(&events, 0, sizeof(events));

	for (i = 0; i < PCKT_RX_BUFS; i++) {
		iov_in[i].iov_base = (void *)knet_h->recv_from_links_buf[i];
		iov_in[i].iov_len = KNET_DATABUFSIZE;

		memset(&msg[i].msg_hdr, 0, sizeof(struct msghdr));

		msg[i].msg_hdr.msg_name = &address[i];
		msg[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage); /* Real value filled in before actual use */
		msg[i].msg_hdr.msg_iov = &iov_in[i];
		msg[i].msg_hdr.msg_iovlen = 1;
	}

	while (!shutdown_in_progress(knet_h)) {
		nev = epoll_wait(knet_h->recv_from_links_epollfd, events, KNET_EPOLL_MAX_EVENTS, knet_h->threads_timer_res / 1000);

		/*
		 * the RX threads only need to notify that there has been at least
		 * one successful run after queue flush has been requested.
		 * See setfwd in handle.c
		 */
		if (get_thread_flush_queue(knet_h, KNET_THREAD_RX) == KNET_THREAD_QUEUE_FLUSH) {
			set_thread_flush_queue(knet_h, KNET_THREAD_RX, KNET_THREAD_QUEUE_FLUSHED);
		}

		/*
		 * we use timeout to detect if thread is shutting down
		 */
		if (nev == 0) {
			continue;
		}

		for (i = 0; i < nev; i++) {
			_handle_recv_from_links(knet_h, events[i].data.fd, msg);
		}
	}

	set_thread_status(knet_h, KNET_THREAD_RX, KNET_THREAD_STOPPED);

	return NULL;
}

ssize_t knet_recv(knet_handle_t knet_h, char *buff, const size_t buff_len, const int8_t channel)
{
	int savederrno = 0;
	ssize_t err = 0;
	struct iovec iov_in;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if (buff == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (buff_len <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (buff_len > KNET_MAX_PACKET_SIZE) {
		errno = EINVAL;
		return -1;
	}

	if (channel < 0) {
		errno = EINVAL;
		return -1;
	}

	if (channel >= KNET_DATAFD_MAX) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!knet_h->sockfd[channel].in_use) {
		savederrno = EINVAL;
		err = -1;
		goto out_unlock;
	}

	memset(&iov_in, 0, sizeof(iov_in));
	iov_in.iov_base = (void *)buff;
	iov_in.iov_len = buff_len;

	err = readv(knet_h->sockfd[channel].sockfd[0], &iov_in, 1);
	savederrno = errno;

out_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}
