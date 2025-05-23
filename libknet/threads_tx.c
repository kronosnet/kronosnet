/*
 * Copyright (C) 2012-2025 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>

#include "compat.h"
#include "compress.h"
#include "crypto.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "transports.h"
#include "transport_common.h"
#include "threads_common.h"
#include "threads_heartbeat.h"
#include "threads_tx.h"
#include "netutils.h"
#include "onwire_v1.h"

/*
 * SEND
 */

static int _dispatch_to_links(knet_handle_t knet_h, struct knet_host *dst_host, struct knet_mmsghdr *msg, int msgs_to_send)
{
	int link_idx, msg_idx, sent_msgs, prev_sent, progress;
	int err = 0, savederrno = 0, locked = 0;
	unsigned int i;
	struct knet_mmsghdr *cur;
	struct knet_link *cur_link;

	for (link_idx = 0; link_idx < dst_host->active_link_entries; link_idx++) {
		prev_sent = 0;
		progress = 1;
		locked = 0;

		cur_link = &dst_host->link[dst_host->active_links[link_idx]];

		if (cur_link->transport == KNET_TRANSPORT_LOOPBACK) {
			continue;
		}

		savederrno = pthread_mutex_lock(&cur_link->link_stats_mutex);
		if (savederrno) {
			log_err(knet_h, KNET_SUB_TX, "Unable to get stats mutex lock for host %u link %u: %s",
				dst_host->host_id, cur_link->link_id, strerror(savederrno));
			continue;
		}
		locked = 1;

		msg_idx = 0;
		while (msg_idx < msgs_to_send) {
			msg[msg_idx].msg_hdr.msg_name = &cur_link->dst_addr;
			msg[msg_idx].msg_hdr.msg_namelen = knet_h->knet_transport_fd_tracker[cur_link->outsock].sockaddr_len;

			/* Cast for Linux/BSD compatibility */
			for (i=0; i<(unsigned int)msg[msg_idx].msg_hdr.msg_iovlen; i++) {
				cur_link->status.stats.tx_data_bytes += msg[msg_idx].msg_hdr.msg_iov[i].iov_len;
			}
			cur_link->status.stats.tx_data_packets++;
			msg_idx++;
		}

retry:
		cur = &msg[prev_sent];

		sent_msgs = _sendmmsg(dst_host->link[dst_host->active_links[link_idx]].outsock,
				      transport_get_connection_oriented(knet_h, dst_host->link[dst_host->active_links[link_idx]].transport),
				      &cur[0], msgs_to_send - prev_sent, MSG_DONTWAIT | MSG_NOSIGNAL);
		savederrno = errno;

		err = transport_tx_sock_error(knet_h, dst_host->link[dst_host->active_links[link_idx]].transport, dst_host->link[dst_host->active_links[link_idx]].outsock, KNET_SUB_TX, sent_msgs, savederrno);
		switch(err) {
			case KNET_TRANSPORT_SOCK_ERROR_INTERNAL:
				cur_link->status.stats.tx_data_errors++;
				goto out_unlock;
				break;
			case KNET_TRANSPORT_SOCK_ERROR_IGNORE:
				break;
			case KNET_TRANSPORT_SOCK_ERROR_RETRY:
				cur_link->status.stats.tx_data_retries++;
				goto retry;
				break;
		}

		prev_sent = prev_sent + sent_msgs;

		if ((sent_msgs >= 0) && (prev_sent < msgs_to_send)) {
			if ((sent_msgs) || (progress)) {
				if (sent_msgs) {
					progress = 1;
				} else {
					progress = 0;
				}
				log_trace(knet_h, KNET_SUB_TX, "Unable to send all (%d/%d) data packets to host %s (%u) link %s:%s (%u)",
					  sent_msgs, msg_idx,
					  dst_host->name, dst_host->host_id,
					  dst_host->link[dst_host->active_links[link_idx]].status.dst_ipaddr,
					  dst_host->link[dst_host->active_links[link_idx]].status.dst_port,
					  dst_host->link[dst_host->active_links[link_idx]].link_id);
				goto retry;
			}
			if (!progress) {
				savederrno = EAGAIN;
				err = -1;
				goto out_unlock;
			}
		}

		if ((dst_host->link_handler_policy == KNET_LINK_POLICY_RR) &&
		    (dst_host->active_link_entries > 1)) {
			uint8_t cur_link_id = dst_host->active_links[0];

			memmove(&dst_host->active_links[0], &dst_host->active_links[1], KNET_MAX_LINK - 1);
			dst_host->active_links[dst_host->active_link_entries - 1] = cur_link_id;

			break;
		}
		pthread_mutex_unlock(&cur_link->link_stats_mutex);
		locked = 0;
	}

out_unlock:
	if (locked) {
		pthread_mutex_unlock(&cur_link->link_stats_mutex);
	}
	errno = savederrno;
	return err;
}

static int _dispatch_to_local(knet_handle_t knet_h, unsigned char *data, size_t inlen, int8_t channel)
{
	int err = 0, savederrno = 0;
	const unsigned char *buf = data;
	ssize_t buflen = inlen;
	struct knet_link *local_link = knet_h->host_index[knet_h->host_id]->link;
	struct iovec iov_out[2];
	uint32_t cur_iov = 0;
	struct knet_datafd_header datafd_hdr;

	if (knet_h->sockfd[channel].flags & KNET_DATAFD_FLAG_RX_RETURN_INFO) {
		memset(&datafd_hdr, 0, sizeof(datafd_hdr));
		datafd_hdr.size = sizeof(datafd_hdr);
		datafd_hdr.src_nodeid = knet_h->host_id;
		iov_out[0].iov_base = &datafd_hdr;
		iov_out[0].iov_len = sizeof(datafd_hdr);
		cur_iov++;
	}
	iov_out[cur_iov].iov_base = (void *)buf;
	iov_out[cur_iov].iov_len = buflen;

	err = writev_all(knet_h, knet_h->sockfd[channel].sockfd[knet_h->sockfd[channel].is_created], iov_out, cur_iov+1, local_link, KNET_SUB_TRANSP_LOOPBACK);
	savederrno = errno;
	if (err < 0) {
		log_err(knet_h, KNET_SUB_TRANSP_LOOPBACK, "send local failed. error=%s\n", strerror(errno));
		local_link->status.stats.tx_data_errors++;
		goto out;
	}
	if (err == buflen) {
		local_link->status.stats.tx_data_packets++;
		local_link->status.stats.tx_data_bytes += inlen;
	}
out:
	errno = savederrno;
	return err;
}

static int _prep_tx_bufs(knet_handle_t knet_h,
			  struct knet_header *inbuf, uint8_t onwire_ver,
			  unsigned char *data, size_t inlen, uint32_t data_checksum,
			  seq_num_t tx_seq_num, int8_t channel, int bcast, int data_compressed,
			  int *msgs_to_send, struct iovec iov_out[PCKT_FRAG_MAX][2], int *iovcnt_out)
{
	int err = 0, savederrno = 0;
	unsigned int temp_data_mtu;

	if (!knet_h->data_mtu) {
		/*
		 * using MIN_MTU_V4 for data mtu is not completely accurate but safe enough
		 */
		log_debug(knet_h, KNET_SUB_TX,
			  "Received data packet but data MTU is still unknown."
			  " Packet might not be delivered."
			  " Assuming minimum IPv4 MTU (%d)",
			  KNET_PMTUD_MIN_MTU_V4);
		temp_data_mtu = KNET_PMTUD_MIN_MTU_V4;
	} else {
		/*
		 * take a copy of the mtu to avoid value changing under
		 * our feet while we are sending a fragmented pckt
		 */
		temp_data_mtu = knet_h->data_mtu;
	}

	if (knet_h->onwire_ver_remap) {
		prep_tx_bufs_v1(knet_h, inbuf, data, inlen, data_checksum, temp_data_mtu, tx_seq_num, channel, bcast, data_compressed, msgs_to_send, iov_out, iovcnt_out);
	} else {
		switch (onwire_ver) {
			case 1:
				prep_tx_bufs_v1(knet_h, inbuf, data, inlen, data_checksum, temp_data_mtu, tx_seq_num, channel, bcast, data_compressed, msgs_to_send, iov_out, iovcnt_out);
				break;
			default: /* this should never hit as filters are in place in the calling functions */
				log_warn(knet_h, KNET_SUB_TX, "preparing data onwire version %u not supported", onwire_ver);
				savederrno = EINVAL;
				err = -1;
				goto out;
				break;
		}
	}

out:
	errno = savederrno;
	return err;
}

static int _compress_data(knet_handle_t knet_h, unsigned char* data, size_t *inlen, int *data_compressed)
{
	int err = 0, savederrno = 0;
	int stats_locked = 0, stats_err = 0;
	size_t cmp_outlen = KNET_DATABUFSIZE_COMPRESS;
	struct timespec start_time;
	struct timespec end_time;
	uint64_t compress_time;

	/*
	 * compress data
	 */
	if (knet_h->compress_model > 0) {
		if (*inlen > knet_h->compress_threshold) {
			clock_gettime(CLOCK_MONOTONIC, &start_time);
			err = compress(knet_h,
				       data, *inlen,
				       knet_h->send_to_links_buf_compress, (ssize_t *)&cmp_outlen);

			savederrno = errno;
			clock_gettime(CLOCK_MONOTONIC, &end_time);
			timespec_diff(start_time, end_time, &compress_time);

			stats_err = pthread_mutex_lock(&knet_h->handle_stats_mutex);
			if (stats_err < 0) {
				log_err(knet_h, KNET_SUB_TX, "Unable to get mutex lock: %s", strerror(stats_err));
				err = -1;
				savederrno = stats_err;
				goto out;
			}
			stats_locked = 1;
			/* Collect stats */

			if (compress_time < knet_h->stats.tx_compress_time_min) {
				knet_h->stats.tx_compress_time_min = compress_time;
			}
			if (compress_time > knet_h->stats.tx_compress_time_max) {
				knet_h->stats.tx_compress_time_max = compress_time;
			}
			knet_h->stats.tx_compress_time_ave =
				(unsigned long long)(knet_h->stats.tx_compress_time_ave * knet_h->stats.tx_compressed_packets +
				 compress_time) / (knet_h->stats.tx_compressed_packets+1);
			if (err < 0) {
				knet_h->stats.tx_failed_to_compress++;
				log_warn(knet_h, KNET_SUB_COMPRESS, "Compression failed (%d): %s", err, strerror(savederrno));
			} else {
				knet_h->stats.tx_compressed_packets++;
				knet_h->stats.tx_compressed_original_bytes += *inlen;
				knet_h->stats.tx_compressed_size_bytes += cmp_outlen;

				if (cmp_outlen < *inlen) {
					memmove(data, knet_h->send_to_links_buf_compress, cmp_outlen);
					*inlen = cmp_outlen;
					*data_compressed = 1;
				} else {
					knet_h->stats.tx_unable_to_compress++;
				}
			}
		}
		if (!*data_compressed) {
			if (!stats_locked) {
				stats_err = pthread_mutex_lock(&knet_h->handle_stats_mutex);
				if (stats_err < 0) {
					log_err(knet_h, KNET_SUB_TX, "Unable to get mutex lock: %s", strerror(stats_err));
					err = -1;
					savederrno = stats_err;
					goto out;
				}
				stats_locked = 1;
			}
			knet_h->stats.tx_uncompressed_packets++;
		}
		if (stats_locked) {
			pthread_mutex_unlock(&knet_h->handle_stats_mutex);
		}
	}

out:
	errno = savederrno;
	return err;
}

static int _encrypt_bufs(knet_handle_t knet_h, int msgs_to_send, struct iovec iov_out[PCKT_FRAG_MAX][2], int *iovcnt_out)
{
	int err = 0, savederrno = 0, stats_err = 0;
	struct timespec start_time;
	struct timespec end_time;
	uint64_t crypt_time;
	uint8_t frag_idx = 0;
	size_t outlen, uncrypted_frag_size;
	int j;

	if (knet_h->crypto_in_use_config) {
		while (frag_idx < msgs_to_send) {
			clock_gettime(CLOCK_MONOTONIC, &start_time);
			if (crypto_encrypt_and_signv(
					knet_h,
					iov_out[frag_idx], *iovcnt_out,
					knet_h->send_to_links_buf_crypt[frag_idx],
					(ssize_t *)&outlen) < 0) {
				log_debug(knet_h, KNET_SUB_TX, "Unable to encrypt packet");
				savederrno = ECHILD;
				err = -1;
				goto out;
			}
			clock_gettime(CLOCK_MONOTONIC, &end_time);
			timespec_diff(start_time, end_time, &crypt_time);

			stats_err = pthread_mutex_lock(&knet_h->handle_stats_mutex);
			if (stats_err < 0) {
				log_err(knet_h, KNET_SUB_TX, "Unable to get mutex lock: %s", strerror(stats_err));
				err = -1;
				savederrno = stats_err;
				goto out;
			}

			if (crypt_time < knet_h->stats.tx_crypt_time_min) {
				knet_h->stats.tx_crypt_time_min = crypt_time;
			}
			if (crypt_time > knet_h->stats.tx_crypt_time_max) {
				knet_h->stats.tx_crypt_time_max = crypt_time;
			}
			knet_h->stats.tx_crypt_time_ave =
				(knet_h->stats.tx_crypt_time_ave * knet_h->stats.tx_crypt_packets +
				 crypt_time) / (knet_h->stats.tx_crypt_packets+1);

			uncrypted_frag_size = 0;
			for (j=0; j < *iovcnt_out; j++) {
				uncrypted_frag_size += iov_out[frag_idx][j].iov_len;
			}
			knet_h->stats.tx_crypt_byte_overhead += (outlen - uncrypted_frag_size);
			knet_h->stats.tx_crypt_packets++;
			pthread_mutex_unlock(&knet_h->handle_stats_mutex);

			iov_out[frag_idx][0].iov_base = knet_h->send_to_links_buf_crypt[frag_idx];
			iov_out[frag_idx][0].iov_len = outlen;
			frag_idx++;
		}
		*iovcnt_out = 1;
	}
out:
	errno = savederrno;
	return err;
}

static int _get_tx_seq_num(knet_handle_t knet_h, seq_num_t *tx_seq_num)
{
	int savederrno = 0;

	savederrno = pthread_mutex_lock(&knet_h->tx_seq_num_mutex);
	if (savederrno) {
		log_debug(knet_h, KNET_SUB_TX, "Unable to get seq mutex lock");
		errno = savederrno;
		return -1;
	}

	knet_h->tx_seq_num++;
	/*
	 * force seq_num 0 to detect a node that has crashed and rejoining
	 * the knet instance. seq_num 0 will clear the buffers in the RX
	 * thread
	 */
	if (knet_h->tx_seq_num == 0) {
		knet_h->tx_seq_num++;
	}
	/*
	 * cache the value in locked context
	 */
	*tx_seq_num = knet_h->tx_seq_num;
	pthread_mutex_unlock(&knet_h->tx_seq_num_mutex);

	/*
	 * forcefully broadcast a ping to all nodes every SEQ_MAX / 8
	 * pckts.
	 * this solves 2 problems:
	 * 1) on TX socket overloads we generate extra pings to keep links alive
	 * 2) in 3+ nodes setup, where all the traffic is flowing between node 1 and 2,
	 *    node 3+ will be able to keep in sync on the TX seq_num even without
	 *    receiving traffic or pings in betweens. This avoids issues with
	 *    rollover of the circular buffer
	 */

	if (*tx_seq_num % (SEQ_MAX / 8) == 0) {
		_send_pings(knet_h, 0);
	}
	return 0;
}


static int _get_data_dests(knet_handle_t knet_h, unsigned char* data, size_t inlen,
			   int8_t *channel, int *bcast, int *send_local,
			   knet_node_id_t *dst_host_ids, size_t *dst_host_ids_entries,
			   int is_sync)
{
	int err = 0, savederrno = 0;
	knet_node_id_t dst_host_ids_temp[KNET_MAX_HOST];	/* store destinations from filter */
	size_t dst_host_ids_entries_temp = 0;
	size_t dst_host_ids_entries_temp2 = 0;			/* workaround gcc here */
	struct knet_host *dst_host;
	size_t host_idx;

	if (knet_h->dst_host_filter_fn) {
		*bcast = knet_h->dst_host_filter_fn(
				knet_h->dst_host_filter_fn_private_data,
				data,
				inlen,
				KNET_NOTIFY_TX,
				knet_h->host_id,
				knet_h->host_id,
				channel,
				dst_host_ids_temp,
				&dst_host_ids_entries_temp);
		if (*bcast < 0) {
			log_debug(knet_h, KNET_SUB_TX, "Error from dst_host_filter_fn: %d", *bcast);
			savederrno = EFAULT;
			err = -1;
			goto out;
		}

		if ((!*bcast) && (!dst_host_ids_entries_temp)) {
			log_debug(knet_h, KNET_SUB_TX, "Message is unicast but no dst_host_ids_entries");
			savederrno = EINVAL;
			err = -1;
			goto out;
		}

		if ((!*bcast) &&
		    (dst_host_ids_entries_temp > KNET_MAX_HOST)) {
			log_debug(knet_h, KNET_SUB_TX, "dst_host_filter_fn returned too many destinations");
			savederrno = EINVAL;
			err = -1;
			goto out;
		}

		if (is_sync) {
			if ((*bcast) ||
			    ((!*bcast) && (dst_host_ids_entries_temp > 1))) {
				log_debug(knet_h, KNET_SUB_TX, "knet_send_sync is only supported with unicast packets for one destination");
				savederrno = E2BIG;
				err = -1;
				goto out;
			}
		}
	}

	/*
	 * check destinations hosts before spending time
	 * in fragmenting/encrypting packets to save
	 * time processing data for unreachable hosts.
	 * for unicast, also remap the destination data
	 * to skip unreachable hosts.
	 */

	if (!*bcast) {
		*dst_host_ids_entries = dst_host_ids_entries_temp2;
		for (host_idx = 0; host_idx < dst_host_ids_entries_temp; host_idx++) {
			dst_host = knet_h->host_index[dst_host_ids_temp[host_idx]];
			if (!dst_host) {
				continue;
			}
			if ((dst_host->host_id == knet_h->host_id) &&
			    (knet_h->has_loop_link)) {
				*send_local = 1;
			}
			if (!((dst_host->host_id == knet_h->host_id) &&
			     (knet_h->has_loop_link)) &&
			    dst_host->status.reachable) {
				dst_host_ids[dst_host_ids_entries_temp2] = dst_host_ids_temp[host_idx];
				dst_host_ids_entries_temp2++;
			}
		}
		if ((!dst_host_ids_entries_temp2) && (!*send_local)) {
			savederrno = EHOSTDOWN;
			err = -1;
			goto out;
		}
		*dst_host_ids_entries = dst_host_ids_entries_temp2;
	} else {
		*bcast = 0;
		*send_local = 0;
		for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
			if ((dst_host->host_id == knet_h->host_id) &&
			    (knet_h->has_loop_link)) {
				*send_local = 1;
			}
			if (!(dst_host->host_id == knet_h->host_id &&
			      knet_h->has_loop_link) &&
			    dst_host->status.reachable) {
				*bcast = 1;
			}
		}
		if ((!*bcast) && (!*send_local)) {
			savederrno = EHOSTDOWN;
			err = -1;
			goto out;
		}
	}

out:
	errno = savederrno;
	return err;
}

static int _prep_and_send_msgs(knet_handle_t knet_h, int bcast, knet_node_id_t *dst_host_ids, size_t dst_host_ids_entries, int msgs_to_send, struct iovec iov_out[PCKT_FRAG_MAX][2], int iovcnt_out)
{
	int err = 0, savederrno = 0;
	struct knet_host *dst_host;
	struct knet_mmsghdr msg[PCKT_FRAG_MAX];
	int msg_idx;
	size_t host_idx;

	memset(&msg, 0, sizeof(msg));

	msg_idx = 0;

	while (msg_idx < msgs_to_send) {
		msg[msg_idx].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage); /* this will set properly in _dispatch_to_links() */
		msg[msg_idx].msg_hdr.msg_iov = &iov_out[msg_idx][0];
		msg[msg_idx].msg_hdr.msg_iovlen = iovcnt_out;
		msg_idx++;
	}

	if (!bcast) {
		for (host_idx = 0; host_idx < dst_host_ids_entries; host_idx++) {
			dst_host = knet_h->host_index[dst_host_ids[host_idx]];

			err = _dispatch_to_links(knet_h, dst_host, &msg[0], msgs_to_send);
			savederrno = errno;
			if (err) {
				goto out;
			}
		}
	} else {
		for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
			if (dst_host->status.reachable) {
				err = _dispatch_to_links(knet_h, dst_host, &msg[0], msgs_to_send);
				savederrno = errno;
				if (err) {
					goto out;
				}
			}
		}
	}

out:
	errno = savederrno;
	return err;
}

static int _parse_recv_from_sock(knet_handle_t knet_h, size_t inlen, int8_t channel, uint8_t onwire_ver, int is_sync)
{
	int err = 0, savederrno = 0;
	struct knet_header *inbuf = knet_h->recv_from_sock_buf; /* all TX packets are stored here regardless of the onwire */
	unsigned char *data;					/* onwire neutrual pointer to data to send */
	int data_compressed = 0;				/* track data compression to fill the header */
	seq_num_t tx_seq_num;
	uint32_t data_checksum = 0;				/* used only for debugging at the moment */

	int bcast = 1;						/* assume all packets are to be broadcasted unless filter tells us differently */
	knet_node_id_t dst_host_ids[KNET_MAX_HOST];		/* store destinations from filter */
	size_t dst_host_ids_entries = 0;
	int send_local = 0;					/* send packets to loopback */

	struct iovec iov_out[PCKT_FRAG_MAX][2];
	int iovcnt_out = 2;
	int msgs_to_send = 0;

	if (knet_h->enabled != 1) {
		log_debug(knet_h, KNET_SUB_TX, "Received data packet but forwarding is disabled");
		savederrno = ECANCELED;
		err = -1;
		goto out;
	}

	if (knet_h->onwire_ver_remap) {
		data = get_data_v1(knet_h, inbuf);
	} else {
		switch (onwire_ver) {
			case 1:
				data = get_data_v1(knet_h, inbuf);
				break;
			default: /* this should never hit as filters are in place in the calling functions */
				log_warn(knet_h, KNET_SUB_TX, "preparing data onwire version %u not supported", onwire_ver);
				savederrno = EINVAL;
				err = -1;
				goto out;
				break;
		}
	}

#ifdef ONWIRE_V1_EXTRA_DEBUG
	data_checksum = compute_chksum(data, inlen);
#endif

	err = _get_data_dests(knet_h, data, inlen,
			      &channel, &bcast, &send_local,
			      dst_host_ids, &dst_host_ids_entries,
			      is_sync);
	if (err < 0) {
		savederrno = errno;
		goto out;
	}

	/* Send to localhost if appropriate and enabled */
	if (send_local) {
		err = _dispatch_to_local(knet_h, data, inlen, channel);
		if (err < 0) {
			savederrno = errno;
			goto out;
		}
	}

	err = _compress_data(knet_h, data, &inlen, &data_compressed);
	if (err < 0) {
		savederrno = errno;
		goto out;
	}

	err = _get_tx_seq_num(knet_h, &tx_seq_num);
	if (err < 0) {
		savederrno = errno;
		goto out;
	}

	err = _prep_tx_bufs(knet_h, inbuf, onwire_ver, data, inlen, data_checksum, tx_seq_num, channel, bcast, data_compressed, &msgs_to_send, iov_out, &iovcnt_out);
	if (err < 0) {
		savederrno = errno;
		goto out;
	}

	err = _encrypt_bufs(knet_h, msgs_to_send, iov_out, &iovcnt_out);
	if (err < 0) {
		savederrno = errno;
		goto out;
	}

	err = _prep_and_send_msgs(knet_h, bcast, dst_host_ids, dst_host_ids_entries, msgs_to_send, iov_out, iovcnt_out);
	if (err < 0) {
		savederrno = errno;
		goto out;
	}

out:
	errno = savederrno;
	return err;
}

static void _handle_send_to_links(knet_handle_t knet_h, int sockfd, uint8_t onwire_ver, int8_t channel)
{
	ssize_t inlen = 0;
	int savederrno = 0, docallback = 0;
	struct iovec iov_in;
	struct msghdr msg;
	struct sockaddr_storage address;

	memset(&iov_in, 0, sizeof(iov_in));

	if (knet_h->onwire_ver_remap) {
		iov_in.iov_base = (void *)get_data_v1(knet_h, knet_h->recv_from_sock_buf);
		iov_in.iov_len = KNET_MAX_PACKET_SIZE;
	} else {
		switch (onwire_ver) {
			case 1:
				iov_in.iov_base = (void *)get_data_v1(knet_h, knet_h->recv_from_sock_buf);
				iov_in.iov_len = KNET_MAX_PACKET_SIZE;
				break;
			default:
				log_warn(knet_h, KNET_SUB_TX, "preparing data onwire version %u not supported", onwire_ver);
				break;
		}
	}

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = &address;
	msg.msg_namelen = knet_h->knet_transport_fd_tracker[sockfd].sockaddr_len;
	msg.msg_iov = &iov_in;
	msg.msg_iovlen = 1;

	if ((channel >= 0) &&
	    (channel < KNET_DATAFD_MAX) &&
	    (!knet_h->sockfd[channel].is_socket)) {
		inlen = readv(sockfd, msg.msg_iov, 1);
	} else {
		inlen = recvmsg(sockfd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (msg.msg_flags & MSG_TRUNC) {
			log_warn(knet_h, KNET_SUB_TX, "Received truncated message from sock %d. Discarding", sockfd);
			return;
		}
	}

	if (inlen == 0) {
		savederrno = 0;
		docallback = 1;
	} else if (inlen < 0) {
		struct epoll_event ev;

		savederrno = errno;
		docallback = 1;
		memset(&ev, 0, sizeof(struct epoll_event));

		if (epoll_ctl(knet_h->send_to_links_epollfd,
			      EPOLL_CTL_DEL, knet_h->sockfd[channel].sockfd[knet_h->sockfd[channel].is_created], &ev)) {
			log_err(knet_h, KNET_SUB_TX, "Unable to del datafd %d from linkfd epoll pool: %s",
				knet_h->sockfd[channel].sockfd[0], strerror(savederrno));
		} else {
			knet_h->sockfd[channel].has_error = 1;
		}
	} else {
		_parse_recv_from_sock(knet_h, inlen, channel, onwire_ver, 0);
	}

	if (docallback) {
		knet_h->sock_notify_fn(knet_h->sock_notify_fn_private_data,
				       knet_h->sockfd[channel].sockfd[0],
				       channel,
				       KNET_NOTIFY_TX,
				       inlen,
				       savederrno);
	}
}

void *_handle_send_to_links_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS + 1]; /* see _init_epolls for + 1 */
	int i, nev;
	int flush, flush_queue_limit;
	int8_t channel;
	uint8_t onwire_ver;

	set_thread_status(knet_h, KNET_THREAD_TX, KNET_THREAD_STARTED);

	memset(&events, 0, sizeof(events));

	flush_queue_limit = 0;

	while (!shutdown_in_progress(knet_h)) {
		nev = epoll_wait(knet_h->send_to_links_epollfd, events, KNET_EPOLL_MAX_EVENTS + 1, knet_h->threads_timer_res / 1000);

		flush = get_thread_flush_queue(knet_h, KNET_THREAD_TX);

		/*
		 * we use timeout to detect if thread is shutting down
		 */
		if (nev == 0) {
			/*
			 * ideally we want to communicate that we are done flushing
			 * the queue when we have an epoll timeout event
			 */
			if (flush == KNET_THREAD_QUEUE_FLUSH) {
				set_thread_flush_queue(knet_h, KNET_THREAD_TX, KNET_THREAD_QUEUE_FLUSHED);
				flush_queue_limit = 0;
			}
			continue;
		}

		/*
		 * fall back in case the TX sockets will continue receive traffic
		 * and we do not hit an epoll timeout.
		 *
		 * allow up to a 100 loops to flush queues, then we give up.
		 * there might be more clean ways to do it by checking the buffer queue
		 * on each socket, but we have tons of sockets and calculations can go wrong.
		 * Also, why would you disable data forwarding and still send packets?
		 */
		if (flush == KNET_THREAD_QUEUE_FLUSH) {
			if (flush_queue_limit >= 100) {
				log_debug(knet_h, KNET_SUB_TX, "Timeout flushing the TX queue, expect packet loss");
				set_thread_flush_queue(knet_h, KNET_THREAD_TX, KNET_THREAD_QUEUE_FLUSHED);
				flush_queue_limit = 0;
			} else {
				flush_queue_limit++;
			}
		} else {
			flush_queue_limit = 0;
		}

		if (pthread_rwlock_rdlock(&knet_h->global_rwlock) != 0) {
			log_debug(knet_h, KNET_SUB_TX, "Unable to get read lock");
			continue;
		}

		if (pthread_mutex_lock(&knet_h->onwire_mutex)) {
			log_debug(knet_h, KNET_SUB_TX, "Unable to get onwire mutex lock");
			goto out_unlock;
		}
		onwire_ver = knet_h->onwire_ver;
		pthread_mutex_unlock(&knet_h->onwire_mutex);

		for (i = 0; i < nev; i++) {
			for (channel = 0; channel < KNET_DATAFD_MAX; channel++) {
				if ((knet_h->sockfd[channel].in_use) &&
				    (knet_h->sockfd[channel].sockfd[knet_h->sockfd[channel].is_created] == events[i].data.fd)) {
					break;
				}
			}
			if (channel >= KNET_DATAFD_MAX) {
				log_debug(knet_h, KNET_SUB_TX, "No available channels");
				continue; /* channel not found */
			}
			if (pthread_mutex_lock(&knet_h->tx_mutex) != 0) {
				log_debug(knet_h, KNET_SUB_TX, "Unable to get mutex lock");
				continue;
			}
			_handle_send_to_links(knet_h, events[i].data.fd, onwire_ver, channel);
			pthread_mutex_unlock(&knet_h->tx_mutex);
		}
out_unlock:
		pthread_rwlock_unlock(&knet_h->global_rwlock);
	}

	set_thread_status(knet_h, KNET_THREAD_TX, KNET_THREAD_STOPPED);

	return NULL;
}

int knet_send_sync(knet_handle_t knet_h, const char *buff, const size_t buff_len, const int8_t channel)
{
	int savederrno = 0, err = 0;
	uint8_t onwire_ver;

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
		log_err(knet_h, KNET_SUB_TX, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!knet_h->dst_host_filter_fn) {
		savederrno = ENETDOWN;
		err = -1;
		goto out;
	}

	if (!knet_h->sockfd[channel].in_use) {
		savederrno = EINVAL;
		err = -1;
		goto out;
	}

	if (pthread_mutex_lock(&knet_h->onwire_mutex)) {
		log_debug(knet_h, KNET_SUB_TX, "Unable to get onwire mutex lock");
		goto out;
	}
	onwire_ver = knet_h->onwire_ver;
	pthread_mutex_unlock(&knet_h->onwire_mutex);

	savederrno = pthread_mutex_lock(&knet_h->tx_mutex);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_TX, "Unable to get TX mutex lock: %s",
			strerror(savederrno));
		err = -1;
		goto out;
	}

	if (knet_h->onwire_ver_remap) {
		memmove(get_data_v1(knet_h, knet_h->recv_from_sock_buf), buff, buff_len);
	} else {
		switch (onwire_ver) {
			case 1:
				memmove(get_data_v1(knet_h, knet_h->recv_from_sock_buf), buff, buff_len);
				break;
			default:
				log_warn(knet_h, KNET_SUB_TX, "preparing sync data onwire version %u not supported", onwire_ver);
				goto out_tx;
				break;
		}
	}

	err = _parse_recv_from_sock(knet_h, buff_len, channel, onwire_ver, 1);
	savederrno = errno;

out_tx:
	pthread_mutex_unlock(&knet_h->tx_mutex);
out:
	pthread_rwlock_unlock(&knet_h->global_rwlock);

	errno = err ? savederrno : 0;
	return err;
}

ssize_t knet_send(knet_handle_t knet_h, const char *buff, const size_t buff_len, const int8_t channel)
{
	int savederrno = 0;
	ssize_t err = 0;
	struct iovec iov_out[1];

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

	memset(iov_out, 0, sizeof(iov_out));

	iov_out[0].iov_base = (void *)buff;
	iov_out[0].iov_len = buff_len;

	err = writev(knet_h->sockfd[channel].sockfd[0], iov_out, 1);
	savederrno = errno;

out_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}
