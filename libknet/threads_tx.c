/*
 * Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <math.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

#include "compat.h"
#include "crypto.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "transports.h"
#include "threads_common.h"
#include "threads_heartbeat.h"
#include "threads_tx.h"
#include "netutils.h"

/*
 * SEND
 */

static int _dispatch_to_links(knet_handle_t knet_h, struct knet_host *dst_host, struct mmsghdr *msg, int msgs_to_send)
{
	int link_idx, msg_idx, sent_msgs, prev_sent, progress;
	int err = 0, savederrno = 0;
	struct mmsghdr *cur;

	for (link_idx = 0; link_idx < dst_host->active_link_entries; link_idx++) {
		sent_msgs = 0;
		prev_sent = 0;
		progress = 1;

		msg_idx = 0;
		while (msg_idx < msgs_to_send) {
			msg[msg_idx].msg_hdr.msg_name = &dst_host->link[dst_host->active_links[link_idx]].dst_addr;
			msg_idx++;
		}

retry:
		cur = &msg[prev_sent];

		sent_msgs = sendmmsg(dst_host->link[dst_host->active_links[link_idx]].outsock,
				     cur, msgs_to_send - prev_sent, MSG_DONTWAIT | MSG_NOSIGNAL);
		savederrno = errno;

		err = knet_h->transport_ops[dst_host->link[dst_host->active_links[link_idx]].transport_type]->transport_tx_sock_error(knet_h, dst_host->link[dst_host->active_links[link_idx]].outsock, sent_msgs, savederrno);
		switch(err) {
			case -1: /* unrecoverable error */
				goto out_unlock;
				break;
			case 0: /* ignore error and continue */
				break;
			case 1: /* retry to send those same data */
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
				log_debug(knet_h, KNET_SUB_TX, "Unable to send all (%d/%d) data packets to host %s (%u) link %s:%s (%u)",
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
	}

out_unlock:
	errno = savederrno;
	return err;
}

static int _parse_recv_from_sock(knet_handle_t knet_h, int buf_idx, ssize_t inlen, int8_t channel, int is_sync)
{
	ssize_t outlen, frag_len;
	struct knet_host *dst_host;
	uint8_t dst_host_ids_temp[KNET_MAX_HOST];
	size_t dst_host_ids_entries_temp = 0;
	uint8_t dst_host_ids[KNET_MAX_HOST];
	size_t dst_host_ids_entries = 0;
	int bcast = 1;
	struct knet_hostinfo *knet_hostinfo;
	struct iovec iov_out[PCKT_FRAG_MAX];
	uint8_t frag_idx;
	unsigned int temp_data_mtu;
	int host_idx;
	int send_mcast = 0;
	struct knet_header *inbuf;
	int savederrno = 0;
	int err = 0;
	seq_num_t tx_seq_num;
	struct mmsghdr msg[PCKT_FRAG_MAX];
	int msgs_to_send, msg_idx;

	inbuf = knet_h->recv_from_sock_buf[buf_idx];

	if ((knet_h->enabled != 1) &&
	    (inbuf->kh_type != KNET_HEADER_TYPE_HOST_INFO)) { /* data forward is disabled */
		log_debug(knet_h, KNET_SUB_TX, "Received data packet but forwarding is disabled");
		savederrno = ECANCELED;
		err = -1;
		goto out_unlock;
	}

	/*
	 * move this into a separate function to expand on
	 * extra switching rules
	 */
	switch(inbuf->kh_type) {
		case KNET_HEADER_TYPE_DATA:
			if (knet_h->dst_host_filter_fn) {
				bcast = knet_h->dst_host_filter_fn(
						knet_h->dst_host_filter_fn_private_data,
						(const unsigned char *)inbuf->khp_data_userdata,
						inlen,
						KNET_NOTIFY_TX,
						knet_h->host_id,
						knet_h->host_id,
						&channel,
						dst_host_ids_temp,
						&dst_host_ids_entries_temp);
				if (bcast < 0) {
					log_debug(knet_h, KNET_SUB_TX, "Error from dst_host_filter_fn: %d", bcast);
					savederrno = EFAULT;
					err = -1;
					goto out_unlock;
				}

				if ((!bcast) && (!dst_host_ids_entries_temp)) {
					log_debug(knet_h, KNET_SUB_TX, "Message is unicast but no dst_host_ids_entries");
					savederrno = EINVAL;
					err = -1;
					goto out_unlock;
				}
			}
			break;
		case KNET_HEADER_TYPE_HOST_INFO:
			knet_hostinfo = (struct knet_hostinfo *)inbuf->khp_data_userdata;
			if (knet_hostinfo->khi_bcast == KNET_HOSTINFO_UCAST) {
				bcast = 0;
				dst_host_ids_temp[0] = knet_hostinfo->khi_dst_node_id;
				dst_host_ids_entries_temp = 1;
			}
			break;
		default:
			log_warn(knet_h, KNET_SUB_TX, "Receiving unknown messages from socket");
			savederrno = ENOMSG;
			err = -1;
			goto out_unlock;
			break;
	}

	if (is_sync) {
		if ((bcast) ||
		    ((!bcast) && (dst_host_ids_entries_temp > 1))) {
			log_debug(knet_h, KNET_SUB_TX, "knet_send_sync is only supported with unicast packets for one destination");
			savederrno = E2BIG;
			err = -1;
			goto out_unlock;
		}
	}

	/*
	 * check destinations hosts before spending time
	 * in fragmenting/encrypting packets to save
	 * time processing data for unrechable hosts.
	 * for unicast, also remap the destination data
	 * to skip unreachable hosts.
	 */

	if (!bcast) {
		dst_host_ids_entries = 0;
		for (host_idx = 0; host_idx < dst_host_ids_entries_temp; host_idx++) {
			dst_host = knet_h->host_index[dst_host_ids_temp[host_idx]];
			if (!dst_host) {
				continue;
			}
			if (dst_host->status.reachable) {
				dst_host_ids[dst_host_ids_entries] = dst_host_ids_temp[host_idx];
				dst_host_ids_entries++;
			}
		}
		if (!dst_host_ids_entries) {
			savederrno = EHOSTDOWN;
			err = -1;
			goto out_unlock;
		}
	} else {
		send_mcast = 0;
		for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
			if (dst_host->status.reachable) {
				send_mcast = 1;
				break;
			}
		}
		if (!send_mcast) {
			savederrno = EHOSTDOWN;
			err = -1;
			goto out_unlock;
		}
	}

	if (!knet_h->data_mtu) {
		/*
		 * using MIN_MTU_V4 for data mtu is not completely accurate but safe enough
		 */
		log_debug(knet_h, KNET_SUB_TX,
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

	/*
	 * prepare the outgoing buffers
	 */

	frag_len = inlen;
	frag_idx = 0;

	inbuf->khp_data_bcast = bcast;
	inbuf->khp_data_frag_num = ceil((float)inlen / temp_data_mtu);
	inbuf->khp_data_channel = channel;

	if (pthread_mutex_lock(&knet_h->tx_seq_num_mutex)) {
		log_debug(knet_h, KNET_SUB_TX, "Unable to get seq mutex lock");
		goto out_unlock;
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
	tx_seq_num = knet_h->tx_seq_num;
	inbuf->khp_data_seq_num = htons(knet_h->tx_seq_num);
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

	if (tx_seq_num % (SEQ_MAX / 8) == 0) {
		_send_pings(knet_h, 0);
	}

	if (inbuf->khp_data_frag_num > 1) {
		while (frag_idx < inbuf->khp_data_frag_num) {
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
			knet_h->send_to_links_buf[frag_idx]->kh_type = inbuf->kh_type;
			knet_h->send_to_links_buf[frag_idx]->khp_data_seq_num = inbuf->khp_data_seq_num;
			knet_h->send_to_links_buf[frag_idx]->khp_data_frag_num = inbuf->khp_data_frag_num;
			knet_h->send_to_links_buf[frag_idx]->khp_data_bcast = inbuf->khp_data_bcast;
			knet_h->send_to_links_buf[frag_idx]->khp_data_channel = inbuf->khp_data_channel;

			memmove(knet_h->send_to_links_buf[frag_idx]->khp_data_userdata,
				inbuf->khp_data_userdata + (temp_data_mtu * frag_idx),
				iov_out[frag_idx].iov_len - KNET_HEADER_DATA_SIZE);

			frag_len = frag_len - temp_data_mtu;
			frag_idx++;
		}
	} else {
		iov_out[frag_idx].iov_base = (void *)inbuf;
		iov_out[frag_idx].iov_len = frag_len + KNET_HEADER_DATA_SIZE;
	}

	if (knet_h->crypto_instance) {
		frag_idx = 0;
		while (frag_idx < inbuf->khp_data_frag_num) {
			if (crypto_encrypt_and_sign(
					knet_h,
					(const unsigned char *)iov_out[frag_idx].iov_base,
					iov_out[frag_idx].iov_len,
					knet_h->send_to_links_buf_crypt[frag_idx],
					&outlen) < 0) {
				log_debug(knet_h, KNET_SUB_TX, "Unable to encrypt packet");
				savederrno = ECHILD;
				err = -1;
				goto out_unlock;
			}
			iov_out[frag_idx].iov_base = knet_h->send_to_links_buf_crypt[frag_idx];
			iov_out[frag_idx].iov_len = outlen;
			frag_idx++;
		}
	}

	memset(&msg, 0, sizeof(msg));

	msgs_to_send = inbuf->khp_data_frag_num;

	msg_idx = 0;

	while (msg_idx < msgs_to_send) {
		msg[msg_idx].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
		msg[msg_idx].msg_hdr.msg_iov = &iov_out[msg_idx];
		msg[msg_idx].msg_hdr.msg_iovlen = 1;
		msg_idx++;
	}

	if (!bcast) {
		for (host_idx = 0; host_idx < dst_host_ids_entries; host_idx++) {
			dst_host = knet_h->host_index[dst_host_ids[host_idx]];

			err = _dispatch_to_links(knet_h, dst_host, &msg[0], msgs_to_send);
			savederrno = errno;
			if (err) {
				goto out_unlock;
			}
		}
	} else {
		for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
			if (dst_host->status.reachable) {
				err = _dispatch_to_links(knet_h, dst_host, &msg[0], msgs_to_send);
				savederrno = errno;
				if (err) {
					goto out_unlock;
				}
			}
		}
	}

out_unlock:
	errno = savederrno;
	return err;
}

int knet_send_sync(knet_handle_t knet_h, const char *buff, const size_t buff_len, const int8_t channel)
{
	int savederrno = 0, err = 0;

	if (!knet_h) {
		errno = EINVAL;
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

	if (!knet_h->sockfd[channel].in_use) {
		savederrno = EINVAL;
		err = -1;
		goto out;
	}

	savederrno = pthread_mutex_lock(&knet_h->tx_mutex);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_TX, "Unable to get TX mutex lock: %s",
			strerror(savederrno));
		err = -1;
		goto out;
	}

	knet_h->recv_from_sock_buf[0]->kh_type = KNET_HEADER_TYPE_DATA;
	memmove(knet_h->recv_from_sock_buf[0]->khp_data_userdata, buff, buff_len);
	err = _parse_recv_from_sock(knet_h, 0, buff_len, channel, 1);
	savederrno = errno;

	pthread_mutex_unlock(&knet_h->tx_mutex);

out:
	pthread_rwlock_unlock(&knet_h->global_rwlock);

	errno = savederrno;
	return err;
}

static void _handle_send_to_links(knet_handle_t knet_h, int sockfd, int8_t channel, struct mmsghdr *msg, int type)
{
	ssize_t inlen = 0;
	struct iovec iov_in;
	int msg_recv, i;
	int savederrno = 0, docallback = 0;

	if ((channel >= 0) &&
	    (channel < KNET_DATAFD_MAX) &&
	    (!knet_h->sockfd[channel].is_socket)) {
		memset(&iov_in, 0, sizeof(iov_in));
		iov_in.iov_base = (void *)knet_h->recv_from_sock_buf[0]->khp_data_userdata;
		iov_in.iov_len = KNET_MAX_PACKET_SIZE;

		inlen = readv(sockfd, &iov_in, 1);

		if (inlen <= 0) {
			savederrno = errno;
			docallback = 1;
			goto out;
		}

		msg_recv = 1;
		knet_h->recv_from_sock_buf[0]->kh_type = type;
		_parse_recv_from_sock(knet_h, 0, inlen, channel, 0);
	} else {
		msg_recv = recvmmsg(sockfd, msg, PCKT_FRAG_MAX, MSG_DONTWAIT | MSG_NOSIGNAL, NULL);
		if (msg_recv < 0) {
			inlen = msg_recv;
			savederrno = errno;
			docallback = 1;
			goto out;
		}
		for (i = 0; i < msg_recv; i++) {
			inlen = msg[i].msg_len;
			if (inlen  == 0) {
				savederrno = 0;
				docallback = 1;
				goto out;
				break;
			}
			knet_h->recv_from_sock_buf[i]->kh_type = type;
			_parse_recv_from_sock(knet_h, i, inlen, channel, 0);
		}
	}

out:
	if (inlen < 0) {
		struct epoll_event ev;

		memset(&ev, 0, sizeof(struct epoll_event));

		if (epoll_ctl(knet_h->send_to_links_epollfd,
			      EPOLL_CTL_DEL, knet_h->sockfd[channel].sockfd[knet_h->sockfd[channel].is_created], &ev)) {
			log_err(knet_h, KNET_SUB_TX, "Unable to del datafd %d from linkfd epoll pool: %s",
				knet_h->sockfd[channel].sockfd[0], strerror(savederrno));
		} else {
			knet_h->sockfd[channel].has_error = 1;
		}

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
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];
	struct sockaddr_storage address[PCKT_FRAG_MAX];
	struct mmsghdr msg[PCKT_FRAG_MAX];
	struct iovec iov_in[PCKT_FRAG_MAX];
	int i, nev, type;
	int8_t channel;

	memset(&msg, 0, sizeof(struct mmsghdr));

	/* preparing data buffer */
	for (i = 0; i < PCKT_FRAG_MAX; i++) {
		iov_in[i].iov_base = (void *)knet_h->recv_from_sock_buf[i]->khp_data_userdata;
		iov_in[i].iov_len = KNET_MAX_PACKET_SIZE;

		memset(&msg[i].msg_hdr, 0, sizeof(struct msghdr));

		msg[i].msg_hdr.msg_name = &address[i];
		msg[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
		msg[i].msg_hdr.msg_iov = &iov_in[i];
		msg[i].msg_hdr.msg_iovlen = 1;

		knet_h->recv_from_sock_buf[i]->kh_version = KNET_HEADER_VERSION;
		knet_h->recv_from_sock_buf[i]->khp_data_frag_seq = 0;
		knet_h->recv_from_sock_buf[i]->kh_node = knet_h->host_id;

		knet_h->send_to_links_buf[i]->kh_version = KNET_HEADER_VERSION;
		knet_h->send_to_links_buf[i]->khp_data_frag_seq = i + 1;
		knet_h->send_to_links_buf[i]->kh_node = knet_h->host_id;
	}

	while (!shutdown_in_progress(knet_h)) {
		nev = epoll_wait(knet_h->send_to_links_epollfd, events, KNET_EPOLL_MAX_EVENTS + 1, -1);

		if (pthread_rwlock_rdlock(&knet_h->global_rwlock) != 0) {
			log_debug(knet_h, KNET_SUB_TX, "Unable to get read lock");
			continue;
		}

		for (i = 0; i < nev; i++) {
			if (events[i].data.fd == knet_h->hostsockfd[0]) {
				type = KNET_HEADER_TYPE_HOST_INFO;
				channel = -1;
			} else {
				type = KNET_HEADER_TYPE_DATA;
				for (channel = 0; channel < KNET_DATAFD_MAX; channel++) {
					if ((knet_h->sockfd[channel].in_use) &&
					    (knet_h->sockfd[channel].sockfd[knet_h->sockfd[channel].is_created] == events[i].data.fd)) {
						break;
					}
				}
			}
			if (pthread_mutex_lock(&knet_h->tx_mutex) != 0) {
				log_debug(knet_h, KNET_SUB_TX, "Unable to get mutex lock");
				continue;
			}
			_handle_send_to_links(knet_h, events[i].data.fd, channel, &msg[0], type);
			pthread_mutex_unlock(&knet_h->tx_mutex);
		}
		pthread_rwlock_unlock(&knet_h->global_rwlock);
	}

	return NULL;
}
