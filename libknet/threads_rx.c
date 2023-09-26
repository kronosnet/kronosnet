/*
 * Copyright (C) 2012-2023 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <stdio.h>
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
#include "threads_rx.h"
#include "netutils.h"

/*
 * RECV
 */

/*
 *  return 1 if a > b
 *  return -1 if b > a
 *  return 0 if they are equal
 */
static inline int timecmp(struct timespec a, struct timespec b)
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
 * this functions needs to return an index (0 to 7)
 * to a knet_host_defrag_buf. (-1 on errors)
 */

static int find_pckt_defrag_buf(knet_handle_t knet_h, struct knet_header *inbuf)
{
	struct knet_host *src_host = knet_h->host_index[inbuf->kh_node];
	int i, oldest;

	/*
	 * check if there is a buffer already in use handling the same seq_num
	 */
	for (i = 0; i < KNET_DEFRAG_BUFFERS; i++) {
		if (src_host->defrag_buf[i].in_use) {
			if (src_host->defrag_buf[i].pckt_seq == inbuf->khp_data_seq_num) {
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
	if (!_seq_num_lookup(src_host, inbuf->khp_data_seq_num, 1, 0)) {
		errno = ETIME;
		return -1;
	}

	/*
	 * register the pckt as seen
	 */
	_seq_num_set(src_host, inbuf->khp_data_seq_num, 1);

	/*
	 * see if there is a free buffer
	 */
	for (i = 0; i < KNET_DEFRAG_BUFFERS; i++) {
		if (!src_host->defrag_buf[i].in_use) {
			return i;
		}
	}

	/*
	 * at this point, there are no free buffers, the pckt is new
	 * and we need to reclaim a buffer, and we will take the one
	 * with the oldest timestamp. It's as good as any.
	 */

	oldest = 0;

	for (i = 0; i < KNET_DEFRAG_BUFFERS; i++) {
		if (timecmp(src_host->defrag_buf[i].last_update, src_host->defrag_buf[oldest].last_update) < 0) {
			oldest = i;
		}
	}
	src_host->defrag_buf[oldest].in_use = 0;
	return oldest;
}

static int pckt_defrag(knet_handle_t knet_h, struct knet_header *inbuf, ssize_t *len)
{
	struct knet_host_defrag_buf *defrag_buf;
	int defrag_buf_idx;

	defrag_buf_idx = find_pckt_defrag_buf(knet_h, inbuf);
	if (defrag_buf_idx < 0) {
		return 1;
	}

	defrag_buf = &knet_h->host_index[inbuf->kh_node]->defrag_buf[defrag_buf_idx];

	/*
	 * if the buf is not is use, then make sure it's clean
	 */
	if (!defrag_buf->in_use) {
		memset(defrag_buf, 0, sizeof(struct knet_host_defrag_buf));
		defrag_buf->in_use = 1;
		defrag_buf->pckt_seq = inbuf->khp_data_seq_num;
	}

	/*
	 * update timestamp on the buffer
	 */
	clock_gettime(CLOCK_MONOTONIC, &defrag_buf->last_update);

	/*
	 * check if we already received this fragment
	 */
	if (defrag_buf->frag_map[inbuf->khp_data_frag_seq]) {
		/*
		 * if we have received this fragment and we didn't clear the buffer
		 * it means that we don't have all fragments yet
		 */
		return 1;
	}

	/*
	 *  we need to handle the last packet with gloves due to its different size
	 */

	if (inbuf->khp_data_frag_seq == inbuf->khp_data_frag_num) {
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
			       inbuf->khp_data_userdata,
			       *len);
		}
	} else {
		defrag_buf->frag_size = *len;
	}

	if (defrag_buf->frag_size) {
		memmove(defrag_buf->buf + ((inbuf->khp_data_frag_seq - 1) * defrag_buf->frag_size),
		       inbuf->khp_data_userdata, *len);
	}

	defrag_buf->frag_recv++;
	defrag_buf->frag_map[inbuf->khp_data_frag_seq] = 1;

	/*
	 * check if we received all the fragments
	 */
	if (defrag_buf->frag_recv == inbuf->khp_data_frag_num) {
		/*
		 * special case the last pckt
		 */

		if (defrag_buf->last_first) {
			memmove(defrag_buf->buf + ((inbuf->khp_data_frag_num - 1) * defrag_buf->frag_size),
			        defrag_buf->buf + (KNET_MAX_PACKET_SIZE - defrag_buf->last_frag_size),
				defrag_buf->last_frag_size);
		}

		/*
		 * recalculate packet lenght
		 */

		*len = ((inbuf->khp_data_frag_num - 1) * defrag_buf->frag_size) + defrag_buf->last_frag_size;

		/*
		 * copy the pckt back in the user data
		 */
		memmove(inbuf->khp_data_userdata, defrag_buf->buf, *len);

		/*
		 * free this buffer
		 */
		defrag_buf->in_use = 0;
		return 0;
	}

	return 1;
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

static int _fast_data_up(knet_handle_t knet_h, struct knet_host *src_host, struct knet_link *src_link)
{
	if (src_link->received_pong) {
		log_debug(knet_h, KNET_SUB_RX, "host: %u link: %u received data during valid ping/pong activity. Force link up.", src_host->host_id, src_link->link_id);
		_link_updown(knet_h, src_host->host_id, src_link->link_id, src_link->status.enabled, 1, 0);
		return 1;
	}
	// host is not eligible for fast data up
	return 0;
}

static void _parse_recv_from_links(knet_handle_t knet_h, int sockfd, const struct knet_mmsghdr *msg)
{
	int err = 0, savederrno = 0, stats_err = 0;
	ssize_t outlen;
	struct knet_host *src_host;
	struct knet_link *src_link;
	unsigned long long latency_last;
	knet_node_id_t dst_host_ids[KNET_MAX_HOST];
	size_t dst_host_ids_entries = 0;
	int bcast = 1;
	uint64_t decrypt_time = 0;
	struct timespec recvtime;
	struct knet_header *inbuf = msg->msg_hdr.msg_iov->iov_base;
	unsigned char *outbuf = (unsigned char *)msg->msg_hdr.msg_iov->iov_base;
	ssize_t len = msg->msg_len;
	struct iovec iov_out[1];
	int8_t channel;
	seq_num_t recv_seq_num;
	int wipe_bufs = 0;
	int try_decrypt = 0, decrypted = 0, i, found_link = 0;

	for (i = 1; i <= KNET_MAX_CRYPTO_INSTANCES; i++) {
		if (knet_h->crypto_instance[i]) {
			try_decrypt = 1;
			break;
		}
	}

	if ((!try_decrypt) && (knet_h->crypto_only == KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC)) {
		log_debug(knet_h, KNET_SUB_RX, "RX thread configured to accept only crypto packets, but no crypto configs are configured!");
		return;
	}

	if (try_decrypt) {
		struct timespec start_time;
		struct timespec end_time;

		clock_gettime(CLOCK_MONOTONIC, &start_time);
		if (crypto_authenticate_and_decrypt(knet_h,
						    (unsigned char *)inbuf,
						    len,
						    knet_h->recv_from_links_buf_decrypt,
						    &outlen) < 0) {
			log_debug(knet_h, KNET_SUB_RX, "Unable to decrypt/auth packet");
			if (knet_h->crypto_only == KNET_CRYPTO_RX_DISALLOW_CLEAR_TRAFFIC) {
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
			log_debug(knet_h, KNET_SUB_RX, "Attempting to process packet as clear data");
		} else {
			clock_gettime(CLOCK_MONOTONIC, &end_time);
			timespec_diff(start_time, end_time, &decrypt_time);

			len = outlen;
			inbuf = (struct knet_header *)knet_h->recv_from_links_buf_decrypt;
			decrypted = 1;
		}
	}

	if (len < (ssize_t)(KNET_HEADER_SIZE + 1)) {
		log_debug(knet_h, KNET_SUB_RX, "Packet is too short: %ld", (long)len);
		return;
	}

	if (inbuf->kh_version != KNET_HEADER_VERSION) {
		log_debug(knet_h, KNET_SUB_RX, "Packet version does not match");
		return;
	}

	inbuf->kh_node = ntohs(inbuf->kh_node);
	src_host = knet_h->host_index[inbuf->kh_node];
	if (src_host == NULL) {  /* host not found */
		log_debug(knet_h, KNET_SUB_RX, "Unable to find source host for this packet");
		return;
	}

	if ((inbuf->kh_type & KNET_HEADER_TYPE_PMSK) != 0) {
		/* be aware this works only for PING / PONG and PMTUd packets! */
		src_link = src_host->link +
			(inbuf->khp_ping_link % KNET_MAX_LINK);
		if (!_check_rx_acl(knet_h, src_link, msg)) {
			return;
		}
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
	} else { /* data packet */
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

		/* data stats at the top for consistency with TX */
		src_link->status.stats.rx_data_packets++;
		src_link->status.stats.rx_data_bytes += len;

		if (decrypted) {
			stats_err = pthread_mutex_lock(&knet_h->handle_stats_mutex);
			if (stats_err < 0) {
				pthread_mutex_unlock(&src_link->link_stats_mutex);
				log_err(knet_h, KNET_SUB_RX, "Unable to get mutex lock: %s", strerror(stats_err));
				return;
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

		if (!src_host->status.reachable) {
			if (!_fast_data_up(knet_h, src_host, src_link)) {
				pthread_mutex_unlock(&src_link->link_stats_mutex);
				log_debug(knet_h, KNET_SUB_RX, "Source host %u not reachable yet. Discarding packet.", src_host->host_id);
				return;
			}
		}

		inbuf->khp_data_seq_num = ntohs(inbuf->khp_data_seq_num);
		channel = inbuf->khp_data_channel;
		src_host->got_data = 1;

		if (!_seq_num_lookup(src_host, inbuf->khp_data_seq_num, 0, 0)) {
			pthread_mutex_unlock(&src_link->link_stats_mutex);
			if (src_host->link_handler_policy != KNET_LINK_POLICY_ACTIVE) {
				log_debug(knet_h, KNET_SUB_RX, "Packet has already been delivered");
			}
			return;
		}

		if (inbuf->khp_data_frag_num > 1) {
			/*
			 * len as received from the socket also includes extra stuff
			 * that the defrag code doesn't care about. So strip it
			 * here and readd only for repadding once we are done
			 * defragging
			 */
			len = len - KNET_HEADER_DATA_SIZE;
			if (pckt_defrag(knet_h, inbuf, &len)) {
				pthread_mutex_unlock(&src_link->link_stats_mutex);
				return;
			}
			len = len + KNET_HEADER_DATA_SIZE;
		}

		if (inbuf->khp_data_compress) {
			ssize_t decmp_outlen = KNET_DATABUFSIZE_COMPRESS;
			struct timespec start_time;
			struct timespec end_time;
			uint64_t compress_time;

			clock_gettime(CLOCK_MONOTONIC, &start_time);
			err = decompress(knet_h, inbuf->khp_data_compress,
					 (const unsigned char *)inbuf->khp_data_userdata,
					 len - KNET_HEADER_DATA_SIZE,
					 knet_h->recv_from_links_buf_decompress,
					 &decmp_outlen);

			stats_err = pthread_mutex_lock(&knet_h->handle_stats_mutex);
			if (stats_err < 0) {
				pthread_mutex_unlock(&src_link->link_stats_mutex);
				log_err(knet_h, KNET_SUB_RX, "Unable to get mutex lock: %s", strerror(stats_err));
				return;
			}

			clock_gettime(CLOCK_MONOTONIC, &end_time);
			timespec_diff(start_time, end_time, &compress_time);

			if (!err) {
				/* Collect stats */
				if (compress_time < knet_h->stats.rx_compress_time_min) {
					knet_h->stats.rx_compress_time_min = compress_time;
				}
				if (compress_time > knet_h->stats.rx_compress_time_max) {
					knet_h->stats.rx_compress_time_max = compress_time;
				}
				knet_h->stats.rx_compress_time_ave =
					(knet_h->stats.rx_compress_time_ave * knet_h->stats.rx_compressed_packets +
					 compress_time) / (knet_h->stats.rx_compressed_packets+1);

				knet_h->stats.rx_compressed_packets++;
				knet_h->stats.rx_compressed_original_bytes += decmp_outlen;
				knet_h->stats.rx_compressed_size_bytes += len - KNET_HEADER_SIZE;

				memmove(inbuf->khp_data_userdata, knet_h->recv_from_links_buf_decompress, decmp_outlen);
				len = decmp_outlen + KNET_HEADER_DATA_SIZE;
			} else {
				pthread_mutex_unlock(&knet_h->handle_stats_mutex);
				pthread_mutex_unlock(&src_link->link_stats_mutex);
				log_err(knet_h, KNET_SUB_COMPRESS, "Unable to decompress packet (%d): %s",
					err, strerror(errno));
				return;
			}
			pthread_mutex_unlock(&knet_h->handle_stats_mutex);
		}

		if (knet_h->enabled != 1) /* data forward is disabled */
			break;

		if (knet_h->dst_host_filter_fn) {
			size_t host_idx;
			int found = 0;

			bcast = knet_h->dst_host_filter_fn(
					knet_h->dst_host_filter_fn_private_data,
					(const unsigned char *)inbuf->khp_data_userdata,
					len - KNET_HEADER_DATA_SIZE,
					KNET_NOTIFY_RX,
					knet_h->host_id,
					inbuf->kh_node,
					&channel,
					dst_host_ids,
					&dst_host_ids_entries);
			if (bcast < 0) {
				pthread_mutex_unlock(&src_link->link_stats_mutex);
				log_debug(knet_h, KNET_SUB_RX, "Error from dst_host_filter_fn: %d", bcast);
				return;
			}

			if ((!bcast) && (!dst_host_ids_entries)) {
				pthread_mutex_unlock(&src_link->link_stats_mutex);
				log_debug(knet_h, KNET_SUB_RX, "Message is unicast but no dst_host_ids_entries");
				return;
			}

			/* check if we are dst for this packet */
			if (!bcast) {
				if (dst_host_ids_entries > KNET_MAX_HOST) {
					pthread_mutex_unlock(&src_link->link_stats_mutex);
					log_debug(knet_h, KNET_SUB_RX, "dst_host_filter_fn returned too many destinations");
					return;
				}
				for (host_idx = 0; host_idx < dst_host_ids_entries; host_idx++) {
					if (dst_host_ids[host_idx] == knet_h->host_id) {
						found = 1;
						break;
					}
				}
				if (!found) {
					pthread_mutex_unlock(&src_link->link_stats_mutex);
					log_debug(knet_h, KNET_SUB_RX, "Packet is not for us");
					return;
				}
			}
		}

		if (!knet_h->sockfd[channel].in_use) {
			pthread_mutex_unlock(&src_link->link_stats_mutex);
			log_debug(knet_h, KNET_SUB_RX,
				  "received packet for channel %d but there is no local sock connected",
				  channel);
			return;
		}

		outlen = 0;
		memset(iov_out, 0, sizeof(iov_out));

retry:
		iov_out[0].iov_base = (void *) inbuf->khp_data_userdata + outlen;
		iov_out[0].iov_len = len - (outlen + KNET_HEADER_DATA_SIZE);

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
			pthread_mutex_unlock(&src_link->link_stats_mutex);
			return;
		}
		if ((size_t)outlen == iov_out[0].iov_len) {
			_seq_num_set(src_host, inbuf->khp_data_seq_num, 0);
		}
		break;
	case KNET_HEADER_TYPE_PING:
		outlen = KNET_HEADER_PING_SIZE;
		inbuf->kh_type = KNET_HEADER_TYPE_PONG;
		inbuf->kh_node = htons(knet_h->host_id);
		recv_seq_num = ntohs(inbuf->khp_ping_seq_num);
		src_link->status.stats.rx_ping_packets++;
		src_link->status.stats.rx_ping_bytes += len;

		wipe_bufs = 0;

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

		if (knet_h->crypto_in_use_config) {
			if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)inbuf,
						    outlen,
						    knet_h->recv_from_links_buf_crypt,
						    &outlen) < 0) {
				log_debug(knet_h, KNET_SUB_RX, "Unable to encrypt pong packet");
				break;
			}
			outbuf = knet_h->recv_from_links_buf_crypt;
			stats_err = pthread_mutex_lock(&knet_h->handle_stats_mutex);
			if (stats_err < 0) {
				log_err(knet_h, KNET_SUB_RX, "Unable to get mutex lock: %s", strerror(stats_err));
				break;
			}
			knet_h->stats_extra.tx_crypt_pong_packets++;
			pthread_mutex_unlock(&knet_h->handle_stats_mutex);
		}

retry_pong:
		if (src_link->transport_connected) {
			if (transport_get_connection_oriented(knet_h, src_link->transport) == TRANSPORT_PROTO_NOT_CONNECTION_ORIENTED) {
				len = sendto(src_link->outsock, outbuf, outlen, MSG_DONTWAIT | MSG_NOSIGNAL,
					     (struct sockaddr *) &src_link->dst_addr, knet_h->knet_transport_fd_tracker[src_link->outsock].sockaddr_len);
			} else {
				len = sendto(src_link->outsock, outbuf, outlen, MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0);
			}
			savederrno = errno;
			if (len != outlen) {
				err = transport_tx_sock_error(knet_h, src_link->transport, src_link->outsock, KNET_SUB_RX, len, savederrno);
				switch(err) {
					case -1: /* unrecoverable error */
						log_debug(knet_h, KNET_SUB_RX,
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
						goto retry_pong;
						break;
				}
			}
			src_link->status.stats.tx_pong_packets++;
			src_link->status.stats.tx_pong_bytes += outlen;
		}
		break;
	case KNET_HEADER_TYPE_PONG:
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

			src_link->latency_cur_samples++;

			/*
			 * limit to max_samples (precision)
			 */
			if (src_link->latency_cur_samples >= src_link->latency_max_samples) {
				src_link->latency_cur_samples = src_link->latency_max_samples;
			}
			src_link->status.latency =
				(((src_link->status.latency * (src_link->latency_cur_samples - 1)) + (latency_last / 1000llu)) / src_link->latency_cur_samples);

			if (src_link->status.latency < src_link->pong_timeout_adj) {
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
			if (src_link->status.latency > src_link->status.stats.latency_max) {
				src_link->status.stats.latency_max = src_link->status.latency;
			}
			if (src_link->status.latency < src_link->status.stats.latency_min) {
				src_link->status.stats.latency_min = src_link->status.latency;
			}

			/*
			 * those 2 lines below make all latency average calculations consistent and capped to
			 * link precision. In future we will kill the one above to keep only this one in
			 * the stats structure, but for now we leave it around to avoid API/ABI
			 * breakage as we backport the fixes to stable
			 */
			src_link->status.stats.latency_ave = src_link->status.latency;
			src_link->status.stats.latency_samples = src_link->latency_cur_samples;
		}
		break;
	case KNET_HEADER_TYPE_PMTUD:
		src_link->status.stats.rx_pmtu_packets++;
		src_link->status.stats.rx_pmtu_bytes += len;
		outlen = KNET_HEADER_PMTUD_SIZE;
		inbuf->kh_type = KNET_HEADER_TYPE_PMTUD_REPLY;
		inbuf->kh_node = htons(knet_h->host_id);

		if (knet_h->crypto_in_use_config) {
			if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)inbuf,
						    outlen,
						    knet_h->recv_from_links_buf_crypt,
						    &outlen) < 0) {
				log_debug(knet_h, KNET_SUB_RX, "Unable to encrypt PMTUd reply packet");
				break;
			}
			outbuf = knet_h->recv_from_links_buf_crypt;
			stats_err = pthread_mutex_lock(&knet_h->handle_stats_mutex);
			if (stats_err < 0) {
				log_err(knet_h, KNET_SUB_RX, "Unable to get mutex lock: %s", strerror(stats_err));
				break;
			}
			knet_h->stats_extra.tx_crypt_pmtu_reply_packets++;
			pthread_mutex_unlock(&knet_h->handle_stats_mutex);
		}

		/* Unlock so we don't deadlock with tx_mutex */
		pthread_mutex_unlock(&src_link->link_stats_mutex);

		savederrno = pthread_mutex_lock(&knet_h->tx_mutex);
		if (savederrno) {
			log_err(knet_h, KNET_SUB_RX, "Unable to get TX mutex lock: %s", strerror(savederrno));
			goto out_pmtud;
		}
retry_pmtud:
		if (src_link->transport_connected) {
			if (transport_get_connection_oriented(knet_h, src_link->transport) == TRANSPORT_PROTO_NOT_CONNECTION_ORIENTED) {
				len = sendto(src_link->outsock, outbuf, outlen, MSG_DONTWAIT | MSG_NOSIGNAL,
					     (struct sockaddr *) &src_link->dst_addr, knet_h->knet_transport_fd_tracker[src_link->outsock].sockaddr_len);
			} else {
				len = sendto(src_link->outsock, outbuf, outlen, MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0);
			}
			savederrno = errno;
			if (len != outlen) {
				err = transport_tx_sock_error(knet_h, src_link->transport, src_link->outsock, KNET_SUB_RX, len, savederrno);
				stats_err = pthread_mutex_lock(&src_link->link_stats_mutex);
				if (stats_err < 0) {
					log_err(knet_h, KNET_SUB_RX, "Unable to get mutex lock: %s", strerror(stats_err));
					break;
				}
				switch(err) {
					case -1: /* unrecoverable error */
						log_debug(knet_h, KNET_SUB_RX,
							  "Unable to send PMTUd reply (sock: %d) packet (sendto): %d %s. recorded src ip: %s src port: %s dst ip: %s dst port: %s",
							  src_link->outsock, errno, strerror(errno),
							  src_link->status.src_ipaddr, src_link->status.src_port,
							  src_link->status.dst_ipaddr, src_link->status.dst_port);

						src_link->status.stats.tx_pmtu_errors++;
						break;
					case 0: /* ignore error and continue */
						src_link->status.stats.tx_pmtu_errors++;
						break;
					case 1: /* retry to send those same data */
						src_link->status.stats.tx_pmtu_retries++;
						pthread_mutex_unlock(&src_link->link_stats_mutex);
						goto retry_pmtud;
						break;
				}
				pthread_mutex_unlock(&src_link->link_stats_mutex);
			}
		}
		pthread_mutex_unlock(&knet_h->tx_mutex);
out_pmtud:
		return; /* Don't need to unlock link_stats_mutex */
	case KNET_HEADER_TYPE_PMTUD_REPLY:
		src_link->status.stats.rx_pmtu_packets++;
		src_link->status.stats.rx_pmtu_bytes += len;

		/* pmtud_mutex can't be acquired while we hold a link_stats_mutex (ordering) */
		pthread_mutex_unlock(&src_link->link_stats_mutex);

		if (pthread_mutex_lock(&knet_h->pmtud_mutex) != 0) {
			log_debug(knet_h, KNET_SUB_RX, "Unable to get mutex lock");
			break;
		}
		src_link->last_recv_mtu = inbuf->khp_pmtud_size;
		pthread_cond_signal(&knet_h->pmtud_cond);
		pthread_mutex_unlock(&knet_h->pmtud_mutex);
		return;
	default:
		pthread_mutex_unlock(&src_link->link_stats_mutex);
		return;
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
			case KNET_TRANSPORT_RX_ERROR: /* on error */
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
		nev = epoll_wait(knet_h->recv_from_links_epollfd, events, KNET_EPOLL_MAX_EVENTS, KNET_THREADS_TIMERES / 1000);

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
