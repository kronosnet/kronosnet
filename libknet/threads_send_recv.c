/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <math.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "crypto.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "threads_common.h"
#include "threads_send_recv.h"

static void _dispatch_to_links(knet_handle_t knet_h, struct knet_host *dst_host, struct iovec *iov_out)
{
	int link_idx, msg_idx;
	struct mmsghdr msg[PCKT_FRAG_MAX];

	if (pthread_mutex_lock(&dst_host->active_links_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_SEND_T, "Unable to get active links mutex");
		return;
	}

	memset(&msg, 0, sizeof(struct mmsghdr));

	for (link_idx = 0; link_idx < dst_host->active_link_entries; link_idx++) {

		msg_idx = 0;

		/*
		 * TODO: interleave link_idx with msg_name for RR ??
		 */

		while (msg_idx < knet_h->send_to_links_buf[0]->khp_data_frag_num) {
			msg[msg_idx].msg_hdr.msg_name = &dst_host->link[dst_host->active_links[link_idx]].dst_addr;
			msg[msg_idx].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
			msg[msg_idx].msg_hdr.msg_iov = &iov_out[msg_idx];
			msg[msg_idx].msg_hdr.msg_iovlen = 1;
			msg_idx++;
		}

		if (sendmmsg(dst_host->link[dst_host->active_links[link_idx]].listener_sock,
			     msg, msg_idx, MSG_NOSIGNAL) < 0) {	
			log_debug(knet_h, KNET_SUB_SEND_T, "Unable to send data packet to host %s (%u) link %s:%s (%u): %s",
				  dst_host->name, dst_host->host_id,
				  dst_host->link[dst_host->active_links[link_idx]].status.dst_ipaddr,
				  dst_host->link[dst_host->active_links[link_idx]].status.dst_port,
				  dst_host->link[dst_host->active_links[link_idx]].link_id,
				  strerror(errno));
		}

		if ((dst_host->link_handler_policy == KNET_LINK_POLICY_RR) &&
		    (dst_host->active_link_entries > 1)) {
			uint8_t cur_link_id = dst_host->active_links[0];

			memmove(&dst_host->active_links[0], &dst_host->active_links[1], KNET_MAX_LINK - 1);
			dst_host->active_links[dst_host->active_link_entries - 1] = cur_link_id;

			break;
		}
	}

	pthread_mutex_unlock(&dst_host->active_links_mutex);

	return;
}

static void _handle_send_to_links(knet_handle_t knet_h, int sockfd)
{
	ssize_t inlen = 0, outlen, frag_len;
	struct knet_host *dst_host;
	uint16_t dst_host_ids[KNET_MAX_HOST];
	size_t dst_host_ids_entries = 0;
	int bcast = 1;
	struct knet_hostinfo *knet_hostinfo;
	struct iovec iov_in;
	struct iovec iov_out[PCKT_FRAG_MAX];
	uint8_t frag_idx;
	unsigned int temp_data_mtu;

	if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_SEND_T, "Unable to get read lock");
		goto host_unlock;
	}

	memset(&iov_in, 0, sizeof(iov_in));
	iov_in.iov_base = (void *)knet_h->send_to_links_buf[0]->khp_data_userdata;
	iov_in.iov_len = KNET_MAX_PACKET_SIZE;

	inlen = readv(sockfd, &iov_in, 1);

	if (inlen < 0) {
		log_err(knet_h, KNET_SUB_SEND_T, "Unrecoverable error: %s", strerror(errno));
		goto out_unlock;
	}

	if (inlen == 0) {
		log_err(knet_h, KNET_SUB_SEND_T, "Unrecoverable error! Got 0 bytes from socket!");
		/* TODO: disconnection, should never happen! */
		goto out_unlock;
	}

	if ((knet_h->enabled != 1) &&
	    (knet_h->send_to_links_buf[0]->kh_type != KNET_HEADER_TYPE_HOST_INFO)) { /* data forward is disabled */
		log_debug(knet_h, KNET_SUB_SEND_T, "Received data packet but forwarding is disabled");
		goto out_unlock;
	}

	knet_h->send_to_links_buf[0]->kh_node = knet_h->host_id;

	/*
	 * move this into a separate function to expand on
	 * extra switching rules
	 */
	switch(knet_h->send_to_links_buf[0]->kh_type) {
		case KNET_HEADER_TYPE_DATA:
			if (knet_h->dst_host_filter_fn) {
				bcast = knet_h->dst_host_filter_fn(
						knet_h->dst_host_filter_fn_private_data,
						(const unsigned char *)knet_h->send_to_links_buf[0]->khp_data_userdata,
						inlen,
						KNET_DST_HOST_FILTER_TX,
						knet_h->host_id,
						knet_h->send_to_links_buf[0]->kh_node,
						dst_host_ids,
						&dst_host_ids_entries);
				if (bcast < 0) {
					log_debug(knet_h, KNET_SUB_SEND_T, "Error from dst_host_filter_fn: %d", bcast);
					goto out_unlock;
				}

				if ((!bcast) && (!dst_host_ids_entries)) {
					log_debug(knet_h, KNET_SUB_SEND_T, "Message is unicast but no dst_host_ids_entries");
					goto out_unlock;
				}
			}
			knet_h->send_to_links_buf[0]->khp_data_bcast = bcast;
			break;
		case KNET_HEADER_TYPE_HOST_INFO:
			knet_hostinfo = (struct knet_hostinfo *)knet_h->send_to_links_buf[0]->khp_data_userdata;
			if (knet_hostinfo->khi_bcast == KNET_HOSTINFO_UCAST) {
				bcast = 0;
				dst_host_ids[0] = ntohs(knet_hostinfo->khi_dst_node_id);
				dst_host_ids_entries = 1;
			}
			break;
		default:
			log_warn(knet_h, KNET_SUB_SEND_T, "Receiving unknown messages from socket");
			goto out_unlock;
			break;
	}

	if (!knet_h->data_mtu) {
		/*
		 * using MIN_MTU_V4 for data mtu is not completely accurate but safe enough
		 */
		log_debug(knet_h, KNET_SUB_SEND_T,
			  "Received data packet but data MTU is still unknown."
			  " Packet might not be delivered."
			  " Assuming mininum IPv4 mtu (%d)",
			  KNET_PMTUD_MIN_MTU_V4);
		temp_data_mtu = KNET_PMTUD_MIN_MTU_V4;
	} else {
		/*
		 * take a copy of the mtu to avoid value changing under
		 * our feet while we are sending a fragmented pckt
		 */
		temp_data_mtu = knet_h->data_mtu;
	}

	frag_len = inlen;
	frag_idx = 0;

	knet_h->send_to_links_buf[0]->kh_node = htons(knet_h->host_id);
	knet_h->send_to_links_buf[0]->khp_data_frag_num = ceil((float)inlen / temp_data_mtu);

	log_debug(knet_h, KNET_SUB_SEND_T, "Current inlen: %zu data mtu: %u frags: %d",
		  inlen, temp_data_mtu, knet_h->send_to_links_buf[0]->khp_data_frag_num);

	/*
	 * prepare the buffers
	 */
	while (frag_idx < knet_h->send_to_links_buf[0]->khp_data_frag_num) {
		/*
		 * set the iov_base
		 */
		iov_out[frag_idx].iov_base = (void *)knet_h->send_to_links_buf[frag_idx];

		/*
		 * set the len
		 */
		if (frag_len > temp_data_mtu) {
			iov_out[frag_idx].iov_len = temp_data_mtu + KNET_HEADER_DATA_SIZE;
		} else {
			iov_out[frag_idx].iov_len = frag_len + KNET_HEADER_DATA_SIZE;
		}

		/*
		 * copy the frag info on all buffers
		 */
		knet_h->send_to_links_buf[frag_idx]->khp_data_frag_num = knet_h->send_to_links_buf[0]->khp_data_frag_num;
		knet_h->send_to_links_buf[frag_idx]->kh_type = knet_h->send_to_links_buf[0]->kh_type;
		knet_h->send_to_links_buf[frag_idx]->kh_node = knet_h->send_to_links_buf[0]->kh_node;
		knet_h->send_to_links_buf[frag_idx]->khp_data_bcast = knet_h->send_to_links_buf[0]->khp_data_bcast;

		frag_len = frag_len - temp_data_mtu;
		if (frag_idx > 0) {
			memmove(knet_h->send_to_links_buf[frag_idx]->khp_data_userdata,
				knet_h->send_to_links_buf[0]->khp_data_userdata + (temp_data_mtu * frag_idx),
				iov_out[frag_idx].iov_len - KNET_HEADER_DATA_SIZE);
		}

		frag_idx++;
	}

	if (!bcast) {
		int host_idx;

		for (host_idx = 0; host_idx < dst_host_ids_entries; host_idx++) {

			dst_host = knet_h->host_index[dst_host_ids[host_idx]];
			if (!dst_host) {
				log_debug(knet_h, KNET_SUB_SEND_T, "unicast packet, host not found");
				continue;
			}

			knet_h->send_to_links_buf[0]->khp_data_seq_num = htons(++dst_host->ucast_seq_num_tx);

			frag_idx = 0;

			while (frag_idx < knet_h->send_to_links_buf[0]->khp_data_frag_num) {

				knet_h->send_to_links_buf[frag_idx]->khp_data_seq_num = knet_h->send_to_links_buf[0]->khp_data_seq_num;

				if (knet_h->crypto_instance) {
					if (crypto_encrypt_and_sign(
							knet_h,
							(const unsigned char *)knet_h->send_to_links_buf[frag_idx],
							iov_out[frag_idx].iov_len,
							knet_h->send_to_links_buf_crypt[frag_idx],
							&outlen) < 0) {
						log_debug(knet_h, KNET_SUB_SEND_T, "Unable to encrypt unicast packet");
						goto out_unlock;
					}
					iov_out[frag_idx].iov_base = knet_h->send_to_links_buf_crypt[frag_idx];
					iov_out[frag_idx].iov_len = outlen;
				}

				frag_idx++;
			}

			_dispatch_to_links(knet_h, dst_host, iov_out);

		}

	} else {

		knet_h->send_to_links_buf[0]->khp_data_seq_num = htons(++knet_h->bcast_seq_num_tx);

		frag_idx = 0;

		while (frag_idx < knet_h->send_to_links_buf[0]->khp_data_frag_num) {

			knet_h->send_to_links_buf[frag_idx]->khp_data_seq_num = knet_h->send_to_links_buf[0]->khp_data_seq_num;

			if (knet_h->crypto_instance) {
				if (crypto_encrypt_and_sign(
						knet_h,
						(const unsigned char *)knet_h->send_to_links_buf[frag_idx],
						iov_out[frag_idx].iov_len,
						knet_h->send_to_links_buf_crypt[frag_idx],
						&outlen) < 0) {
					log_debug(knet_h, KNET_SUB_SEND_T, "Unable to encrypt unicast packet");
					goto out_unlock;
				}
				iov_out[frag_idx].iov_base = knet_h->send_to_links_buf_crypt[frag_idx];
				iov_out[frag_idx].iov_len = outlen;
			}

			frag_idx++;
		}

		for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
			_dispatch_to_links(knet_h, dst_host, iov_out);
		}

	}

out_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);

host_unlock:
	if ((inlen > 0) && (knet_h->send_to_links_buf[0]->kh_type == KNET_HEADER_TYPE_HOST_INFO)) {
		if (pthread_mutex_lock(&knet_h->host_mutex) != 0)
			log_debug(knet_h, KNET_SUB_SEND_T, "Unable to get mutex lock");
		pthread_cond_signal(&knet_h->host_cond);
		pthread_mutex_unlock(&knet_h->host_mutex);
	}
}

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
	for (i = 0; i < KNET_MAX_LINK; i++) {
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
	if (!_should_deliver(src_host, inbuf->khp_data_bcast, inbuf->khp_data_seq_num, 1)) {
		errno = ETIME;
		return -1;
	}

	/*
	 * register the pckt as seen
	 */
	_has_been_seen(src_host, inbuf->khp_data_bcast, inbuf->khp_data_seq_num);

	/*
	 * see if there is a free buffer
	 */
	for (i = 0; i < KNET_MAX_LINK; i++) {
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

	for (i = 0; i < KNET_MAX_LINK; i++) {
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
		if (errno == EEXIST) {
			log_debug(knet_h, KNET_SUB_LINK_T, "Packet has already been delivered");
		}
		if (errno == ETIME) {
			log_debug(knet_h, KNET_SUB_LINK_T, "Defrag buffer expired");
		}
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

	memmove(defrag_buf->buf + ((inbuf->khp_data_frag_seq - 1) * defrag_buf->frag_size),
	       inbuf->khp_data_userdata, *len);

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

static void _parse_recv_from_links(knet_handle_t knet_h, struct sockaddr_storage *address, int index, ssize_t len)
{
	ssize_t outlen;
	struct knet_host *src_host;
	struct knet_link *src_link;
	unsigned long long latency_last;
	uint16_t dst_host_ids[KNET_MAX_HOST];
	size_t dst_host_ids_entries = 0;
	int bcast = 1;
	struct timespec recvtime;
	struct knet_header *inbuf = knet_h->recv_from_links_buf[index];
	unsigned char *outbuf = (unsigned char *)knet_h->recv_from_links_buf[index];
	struct knet_hostinfo *knet_hostinfo;
	struct iovec iov_out[1];

	if (knet_h->crypto_instance) {
		if (crypto_authenticate_and_decrypt(knet_h,
						    (unsigned char *)inbuf,
						    len,
						    knet_h->recv_from_links_buf_decrypt,
						    &outlen) < 0) {
			log_debug(knet_h, KNET_SUB_LINK_T, "Unable to decrypt/auth packet");
			return;
		}
		len = outlen;
		inbuf = (struct knet_header *)knet_h->recv_from_links_buf_decrypt;
	}

	if (len < (KNET_HEADER_SIZE + 1)) {
		log_debug(knet_h, KNET_SUB_LINK_T, "Packet is too short");
		return;
	}

	if (inbuf->kh_version != KNET_HEADER_VERSION) {
		log_debug(knet_h, KNET_SUB_LINK_T, "Packet version does not match");
		return;
	}

	inbuf->kh_node = ntohs(inbuf->kh_node);
	src_host = knet_h->host_index[inbuf->kh_node];
	if (src_host == NULL) {  /* host not found */
		log_debug(knet_h, KNET_SUB_LINK_T, "Unable to find source host for this packet");
		return;
	}

	src_link = NULL;

	if ((inbuf->kh_type & KNET_HEADER_TYPE_PMSK) != 0) {
		src_link = src_host->link +
				(inbuf->khp_ping_link % KNET_MAX_LINK);
		if (src_link->dynamic == KNET_LINK_DYNIP) {
			if (memcmp(&src_link->dst_addr, address, sizeof(struct sockaddr_storage)) != 0) {
				log_debug(knet_h, KNET_SUB_LINK_T, "host: %u link: %u appears to have changed ip address",
					  src_host->host_id, src_link->link_id);
				memmove(&src_link->dst_addr, address, sizeof(struct sockaddr_storage));
				if (getnameinfo((const struct sockaddr *)&src_link->dst_addr, sizeof(struct sockaddr_storage),
						src_link->status.dst_ipaddr, KNET_MAX_HOST_LEN,
						src_link->status.dst_port, KNET_MAX_PORT_LEN,
						NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
					log_debug(knet_h, KNET_SUB_LINK_T, "Unable to resolve ???");
					snprintf(src_link->status.dst_ipaddr, KNET_MAX_HOST_LEN - 1, "Unknown!!!");
					snprintf(src_link->status.dst_port, KNET_MAX_PORT_LEN - 1, "??");
				}
			}
			src_link->status.dynconnected = 1;
		}
	}

	switch (inbuf->kh_type) {
	case KNET_HEADER_TYPE_HOST_INFO:
	case KNET_HEADER_TYPE_DATA:
		inbuf->khp_data_seq_num = ntohs(inbuf->khp_data_seq_num);

		if (!_should_deliver(src_host, inbuf->khp_data_bcast, inbuf->khp_data_seq_num, 0)) {
			if (src_host->link_handler_policy != KNET_LINK_POLICY_ACTIVE) {
				log_debug(knet_h, KNET_SUB_LINK_T, "Packet has already been delivered");
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
				return;
			}
			len = len + KNET_HEADER_DATA_SIZE;
		}

		if (inbuf->kh_type == KNET_HEADER_TYPE_DATA) {
			if (knet_h->enabled != 1) /* data forward is disabled */
				break;

			if (knet_h->dst_host_filter_fn) {
				int host_idx;
				int found = 0;

				bcast = knet_h->dst_host_filter_fn(
						knet_h->dst_host_filter_fn_private_data,
						(const unsigned char *)inbuf->khp_data_userdata,
						len,
						KNET_DST_HOST_FILTER_RX,
						knet_h->host_id,
						inbuf->kh_node,
						dst_host_ids,
						&dst_host_ids_entries);
				if (bcast < 0) {
					log_debug(knet_h, KNET_SUB_LINK_T, "Error from dst_host_filter_fn: %d", bcast);
					return;
				}

				if ((!bcast) && (!dst_host_ids_entries)) {
					log_debug(knet_h, KNET_SUB_LINK_T, "Message is unicast but no dst_host_ids_entries");
					return;
				}

				/* check if we are dst for this packet */
				if (!bcast) {
					for (host_idx = 0; host_idx < dst_host_ids_entries; host_idx++) {
						if (dst_host_ids[host_idx] == knet_h->host_id) {
							found = 1;
							break;
						}
					}
					if (!found) {
						log_debug(knet_h, KNET_SUB_LINK_T, "Packet is not for us");
						return;
					}
				}
			}
		}

		if (inbuf->kh_type == KNET_HEADER_TYPE_DATA) {
			memset(iov_out, 0, sizeof(iov_out));
			iov_out[0].iov_base = (void *) inbuf->khp_data_userdata;
			iov_out[0].iov_len = len - KNET_HEADER_DATA_SIZE;

			if (writev(knet_h->sockfd, iov_out, 1) == iov_out[0].iov_len) {
				_has_been_delivered(src_host, bcast, inbuf->khp_data_seq_num);
			} else {
				log_debug(knet_h, KNET_SUB_LINK_T, "Packet has not been delivered");
			}
		} else { /* HOSTINFO */
			_has_been_delivered(src_host, bcast, inbuf->khp_data_seq_num);
			knet_hostinfo = (struct knet_hostinfo *)inbuf->khp_data_userdata;
			if (knet_hostinfo->khi_bcast == KNET_HOSTINFO_UCAST) {
				knet_hostinfo->khi_dst_node_id = ntohs(knet_hostinfo->khi_dst_node_id);
			}
			switch(knet_hostinfo->khi_type) {
				case KNET_HOSTINFO_TYPE_LINK_UP_DOWN:
					src_link = src_host->link +
						(knet_hostinfo->khip_link_status_link_id % KNET_MAX_LINK);
					/*
					 * basically if the node is coming back to life from a crash
					 * we should receive a host info where local previous status == remote current status
					 * and so we can detect that node is showing up again
					 * we need to clear cbuffers and notify the node of our status by resending our host info
					 */
					if ((src_link->remoteconnected == KNET_HOSTINFO_LINK_STATUS_UP) &&
					    (src_link->remoteconnected == knet_hostinfo->khip_link_status_status)) {
						src_link->host_info_up_sent = 0;
					}
					src_link->remoteconnected = knet_hostinfo->khip_link_status_status;
					if (src_link->remoteconnected == KNET_HOSTINFO_LINK_STATUS_DOWN) {
						/*
						 * if a host is disconnecting clean, we note that in donnotremoteupdate
						 * so that we don't send host info back immediately but we wait
						 * for the node to send an update when it's alive again
						 */
						src_link->host_info_up_sent = 0;
						src_link->donnotremoteupdate = 1;
					} else {
						src_link->donnotremoteupdate = 0;
					}
					log_debug(knet_h, KNET_SUB_LINK, "host message up/down. from host: %u link: %u remote connected: %u",
						  src_host->host_id,
						  src_link->link_id,
						  src_link->remoteconnected);
					if (_host_dstcache_update_async(knet_h, src_host)) {
						log_debug(knet_h, KNET_SUB_LINK,
							  "Unable to update switch cache for host: %u link: %u remote connected: %u)",
							  src_host->host_id,
							  src_link->link_id,
							  src_link->remoteconnected);
					}
					break;
				case KNET_HOSTINFO_TYPE_LINK_TABLE:
					break;
				default:
					log_warn(knet_h, KNET_SUB_LINK, "Receiving unknown host info message from host %u", src_host->host_id);
					break;
			}
		}
		break;
	case KNET_HEADER_TYPE_PING:
		outlen = KNET_HEADER_PING_SIZE;
		inbuf->kh_type = KNET_HEADER_TYPE_PONG;
		inbuf->kh_node = htons(knet_h->host_id);

		if (knet_h->crypto_instance) {
			if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)inbuf,
						    len,
						    knet_h->recv_from_links_buf_crypt,
						    &outlen) < 0) {
				log_debug(knet_h, KNET_SUB_LINK_T, "Unable to encrypt pong packet");
				break;
			}
			outbuf = knet_h->recv_from_links_buf_crypt;
		}

		sendto(src_link->listener_sock, outbuf, outlen, MSG_DONTWAIT,
				(struct sockaddr *) &src_link->dst_addr,
				sizeof(struct sockaddr_storage));

		break;
	case KNET_HEADER_TYPE_PONG:
		clock_gettime(CLOCK_MONOTONIC, &src_link->status.pong_last);

		memmove(&recvtime, &inbuf->khp_ping_time[0], sizeof(struct timespec));
		timespec_diff(recvtime,
				src_link->status.pong_last, &latency_last);

		src_link->status.latency =
			((src_link->status.latency * src_link->latency_exp) +
			((latency_last / 1000llu) *
				(src_link->latency_fix - src_link->latency_exp))) /
					src_link->latency_fix;

		if (src_link->status.latency < src_link->pong_timeout) {
			if (!src_link->status.connected) {
				if (src_link->received_pong >= src_link->pong_count) {
					log_info(knet_h, KNET_SUB_LINK, "host: %u link: %u is up",
						 src_host->host_id, src_link->link_id);
					_link_updown(knet_h, src_host->host_id, src_link->link_id, src_link->status.enabled, 1);
				} else {
					src_link->received_pong++;
					log_debug(knet_h, KNET_SUB_LINK, "host: %u link: %u received pong: %u",
						  src_host->host_id, src_link->link_id, src_link->received_pong);
				}
			}
		}

		break;
	case KNET_HEADER_TYPE_PMTUD:
		outlen = KNET_HEADER_PMTUD_SIZE;
		inbuf->kh_type = KNET_HEADER_TYPE_PMTUD_REPLY;
		inbuf->kh_node = htons(knet_h->host_id);

		if (knet_h->crypto_instance) {
			if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)inbuf,
						    len,
						    knet_h->recv_from_links_buf_crypt,
						    &outlen) < 0) {
				log_debug(knet_h, KNET_SUB_LINK_T, "Unable to encrypt PMTUd reply packet");
				break;
			}
			outbuf = knet_h->recv_from_links_buf_crypt;
		}

		sendto(src_link->listener_sock, outbuf, outlen, MSG_DONTWAIT,
				(struct sockaddr *) &src_link->dst_addr,
				sizeof(struct sockaddr_storage));

		break;
	case KNET_HEADER_TYPE_PMTUD_REPLY:
		if (pthread_mutex_lock(&knet_h->pmtud_mutex) != 0) {
			log_debug(knet_h, KNET_SUB_LINK_T, "Unable to get mutex lock");
			break;
		}
		src_link->last_recv_mtu = inbuf->khp_pmtud_size;
		pthread_cond_signal(&knet_h->pmtud_cond);
		pthread_mutex_unlock(&knet_h->pmtud_mutex);
		break;
	default:
		return;
	}
}

static void _handle_recv_from_links(knet_handle_t knet_h, int sockfd, struct mmsghdr *msg)
{
	int i, msg_recv;

	if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_LINK_T, "Unable to get read lock");
		return;
	}

	msg_recv = recvmmsg(sockfd, msg, PCKT_FRAG_MAX, MSG_DONTWAIT, NULL);
	if (msg_recv < 0) {
		log_err(knet_h, KNET_SUB_LINK_T, "No message received from recvmmsg: %s", strerror(errno));
		goto exit_unlock;
	}

	for (i = 0; i < msg_recv; i++) {
		_parse_recv_from_links(knet_h, (struct sockaddr_storage *)&msg[i].msg_hdr.msg_name, i, msg[i].msg_len);
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
}

void *_handle_send_to_links_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];
	int i, nev;

	/* preparing data buffer */
	for (i = 0; i < PCKT_FRAG_MAX; i++) {
		knet_h->send_to_links_buf[i]->kh_version = KNET_HEADER_VERSION;
		knet_h->send_to_links_buf[i]->khp_data_frag_seq = i + 1;
	}

	while (!knet_h->fini_in_progress) {
		nev = epoll_wait(knet_h->send_to_links_epollfd, events, KNET_EPOLL_MAX_EVENTS, -1);

		for (i = 0; i < nev; i++) {
			if (events[i].data.fd == knet_h->sockfd) {
				knet_h->send_to_links_buf[0]->kh_type = KNET_HEADER_TYPE_DATA;
			} else {
				knet_h->send_to_links_buf[0]->kh_type = KNET_HEADER_TYPE_HOST_INFO;
			}
			_handle_send_to_links(knet_h, events[i].data.fd);
		}
	}

	return NULL;
}

void *_handle_recv_from_links_thread(void *data)
{
	int i, nev;
	knet_handle_t knet_h = (knet_handle_t) data;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];
	struct sockaddr_storage address[PCKT_FRAG_MAX];
	struct mmsghdr msg[PCKT_FRAG_MAX];
	struct iovec iov_in[PCKT_FRAG_MAX];

	memset(&msg, 0, sizeof(struct mmsghdr));

	for (i = 0; i < PCKT_FRAG_MAX; i++) {
		iov_in[i].iov_base = (void *)knet_h->recv_from_links_buf[i];
		iov_in[i].iov_len = KNET_DATABUFSIZE;

		msg[i].msg_hdr.msg_name = &address[i];
		msg[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
		msg[i].msg_hdr.msg_iov = &iov_in[i];
		msg[i].msg_hdr.msg_iovlen = 1;
	}

	while (!knet_h->fini_in_progress) {
		nev = epoll_wait(knet_h->recv_from_links_epollfd, events, KNET_EPOLL_MAX_EVENTS, -1);

		for (i = 0; i < nev; i++) {
			_handle_recv_from_links(knet_h, events[i].data.fd, msg);
		}
	}

	return NULL;
}
