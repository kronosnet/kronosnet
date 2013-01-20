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

#include "internals.h"
#include "onwire.h"
#include "crypto.h"
#include "common.h"
#include "host.h"
#include "logging.h"
#include "listener.h"
#include "link.h"
#include "threads.h"

#define KNET_PING_TIMERES 200000

static void _handle_tap_to_links(knet_handle_t knet_h, int sockfd)
{
	ssize_t inlen = 0, len, outlen;
	struct knet_host *dst_host;
	int link_idx;
	uint16_t dst_host_ids[KNET_MAX_HOST];
	size_t dst_host_ids_entries = 0;
	int bcast = 1;
	unsigned char *outbuf = (unsigned char *)knet_h->tap_to_links_buf;
	struct knet_hinfo_data *knet_hinfo_data;

	if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_TAP_T, "Unable to get read lock");
		goto host_unlock;
	}

	inlen = read(sockfd, knet_h->tap_to_links_buf->kf_data, KNET_MAX_PACKET_SIZE);

	if (inlen == 0) {
		log_err(knet_h, KNET_SUB_TAP_T, "Unrecoverable error! Got 0 bytes from tap device!");
		/* TODO: disconnection, should never happen! */
		goto out_unlock;
	}

	outlen = len = inlen + KNET_FRAME_SIZE + sizeof(seq_num_t);

	if ((knet_h->enabled != 1) &&
	    (knet_h->tap_to_links_buf->kf_type != KNET_FRAME_HOST_INFO)) { /* data forward is disabled */
		log_debug(knet_h, KNET_SUB_TAP_T, "Received data packet but forwarding is disabled");
		goto out_unlock;
	}

	switch(knet_h->tap_to_links_buf->kf_type) {
		case KNET_FRAME_DATA:
			if (knet_h->dst_host_filter_fn) {
				bcast = knet_h->dst_host_filter_fn(
						(const unsigned char *)knet_h->tap_to_links_buf->kf_data,
						inlen,
						knet_h->tap_to_links_buf->kf_node,
						dst_host_ids,
						&dst_host_ids_entries);
				if (bcast < 0) {
					log_debug(knet_h, KNET_SUB_TAP_T, "Error from dst_host_filter_fn: %d", bcast);
					goto out_unlock;
				}

				if ((!bcast) && (!dst_host_ids_entries)) {
					log_debug(knet_h, KNET_SUB_TAP_T, "Message is unicast but no dst_host_ids_entries");
					goto out_unlock;
				}
			}
			break;
		case KNET_FRAME_HOST_INFO:
			knet_hinfo_data = (struct knet_hinfo_data *)knet_h->tap_to_links_buf->kf_data;
			if (!knet_hinfo_data->khd_bcast) {
				bcast = 0;
				dst_host_ids[0] = ntohs(knet_hinfo_data->khd_dst_node_id);
				dst_host_ids_entries = 1;
			}
			break;
		default:
			log_warn(knet_h, KNET_SUB_TAP_T, "Receiving unknown messages from tap");
			goto out_unlock;
			break;
	}

	if (!bcast) {
		int host_idx;

		for (host_idx = 0; host_idx < dst_host_ids_entries; host_idx++) {
			dst_host = knet_h->host_index[dst_host_ids[host_idx]];
			if (!dst_host) {
				log_debug(knet_h, KNET_SUB_TAP_T, "unicast packet, host not found");
				continue;
			}

			knet_h->tap_to_links_buf->kf_seq_num = htons(++dst_host->ucast_seq_num_tx);

			if (knet_h->crypto_instance) {
				if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)knet_h->tap_to_links_buf,
						    len,
						    knet_h->tap_to_links_buf_crypt,
						    &outlen) < 0) {
					log_debug(knet_h, KNET_SUB_TAP_T, "Unable to encrypt unicast packet");
					goto out_unlock;
				}
				outbuf = knet_h->tap_to_links_buf_crypt;
			}

			for (link_idx = 0; link_idx < dst_host->active_link_entries; link_idx++) {
				sendto(dst_host->link[dst_host->active_links[link_idx]].listener_sock,
						outbuf, outlen, MSG_DONTWAIT,
						(struct sockaddr *) &dst_host->link[dst_host->active_links[link_idx]].dst_addr,
						sizeof(struct sockaddr_storage));

				if ((dst_host->link_handler_policy == KNET_LINK_POLICY_RR) &&
				    (dst_host->active_link_entries > 1)) {
					uint8_t cur_link_id = dst_host->active_links[0];

					memmove(&dst_host->active_links[0], &dst_host->active_links[1], KNET_MAX_LINK - 1);
					dst_host->active_links[dst_host->active_link_entries - 1] = cur_link_id;

					break;
				}
			}
		}
	} else {
		knet_h->tap_to_links_buf->kf_seq_num = htons(++knet_h->bcast_seq_num_tx);

		if (knet_h->crypto_instance) {
			if (crypto_encrypt_and_sign(knet_h,
					    (const unsigned char *)knet_h->tap_to_links_buf,
					    len,
					    knet_h->tap_to_links_buf_crypt,
					    &outlen) < 0) {
				log_debug(knet_h, KNET_SUB_TAP_T, "Unable to encrypt mcast/bcast packet");
				goto out_unlock;
			}
			outbuf = knet_h->tap_to_links_buf_crypt;
		}

		for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
			for (link_idx = 0; link_idx < dst_host->active_link_entries; link_idx++) {
				sendto(dst_host->link[dst_host->active_links[link_idx]].listener_sock,
					outbuf, outlen, MSG_DONTWAIT,
					(struct sockaddr *) &dst_host->link[dst_host->active_links[link_idx]].dst_addr,
					sizeof(struct sockaddr_storage));

				if ((dst_host->link_handler_policy == KNET_LINK_POLICY_RR) &&
				    (dst_host->active_link_entries > 1)) {
					uint8_t cur_link_id = dst_host->active_links[0];

					memmove(&dst_host->active_links[0], &dst_host->active_links[1], KNET_MAX_LINK - 1);
					dst_host->active_links[dst_host->active_link_entries - 1] = cur_link_id;

					break;
				}
			}
		}
	}

out_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);

host_unlock:
	if ((inlen > 0) && (knet_h->tap_to_links_buf->kf_type == KNET_FRAME_HOST_INFO)) {
		if (pthread_mutex_lock(&knet_h->host_mutex) != 0)
			log_debug(knet_h, KNET_SUB_TAP_T, "Unable to get mutex lock");
		pthread_cond_signal(&knet_h->host_cond);
		pthread_mutex_unlock(&knet_h->host_mutex);
	}
}

static void _handle_recv_from_links(knet_handle_t knet_h, int sockfd)
{
	ssize_t len, outlen;
	struct sockaddr_storage address;
	socklen_t addrlen;
	struct knet_host *src_host;
	struct knet_link *src_link;
	unsigned long long latency_last;
	uint16_t dst_host_ids[KNET_MAX_HOST];
	size_t dst_host_ids_entries = 0;
	int bcast = 1;
	struct timespec recvtime;
	unsigned char *outbuf = (unsigned char *)knet_h->recv_from_links_buf;
	struct knet_hinfo_data *knet_hinfo_data;

	if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_LINK_T, "Unable to get read lock");
		return;
	}

	addrlen = sizeof(struct sockaddr_storage);
	len = recvfrom(sockfd, knet_h->recv_from_links_buf, KNET_DATABUFSIZE,
		MSG_DONTWAIT, (struct sockaddr *) &address, &addrlen);

	if (knet_h->crypto_instance) {
		if (crypto_authenticate_and_decrypt(knet_h,
						    (unsigned char *)knet_h->recv_from_links_buf,
						    &len) < 0) {
			log_debug(knet_h, KNET_SUB_LINK_T, "Unable to decrypt/auth packet");
			goto exit_unlock;
		}
	}

	if (len < (KNET_FRAME_SIZE + 1)) {
		log_debug(knet_h, KNET_SUB_LINK_T, "Packet is too short");
		goto exit_unlock;
	}

	if (knet_h->recv_from_links_buf->kf_version != KNET_FRAME_VERSION) {
		log_debug(knet_h, KNET_SUB_LINK_T, "Packet version does not match");
		goto exit_unlock;
	}

	knet_h->recv_from_links_buf->kf_node = ntohs(knet_h->recv_from_links_buf->kf_node);
	src_host = knet_h->host_index[knet_h->recv_from_links_buf->kf_node];
	if (src_host == NULL) {  /* host not found */
		log_debug(knet_h, KNET_SUB_LINK_T, "Unable to find source host for this packet");
		goto exit_unlock;
	}

	src_link = NULL;

	if ((knet_h->recv_from_links_buf->kf_type & KNET_FRAME_PMSK) != 0) {
		src_link = src_host->link +
				(knet_h->recv_from_links_buf->kf_link % KNET_MAX_LINK);
		if (src_link->dynamic == KNET_LINK_DYNIP) {
			if (memcmp(&src_link->dst_addr, &address, sizeof(struct sockaddr_storage)) != 0) {
				log_debug(knet_h, KNET_SUB_LINK_T, "host: %s link: %u appears to have changed ip address",
					  src_host->name, src_link->link_id);
				memcpy(&src_link->dst_addr, &address, sizeof(struct sockaddr_storage));
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

	switch (knet_h->recv_from_links_buf->kf_type) {
	case KNET_FRAME_DATA:
		if (knet_h->enabled != 1) /* data forward is disabled */
			break;

		knet_h->recv_from_links_buf->kf_seq_num = ntohs(knet_h->recv_from_links_buf->kf_seq_num);

		if (knet_h->dst_host_filter_fn) {
			int host_idx;
			int found = 0;

			bcast = knet_h->dst_host_filter_fn(
					(const unsigned char *)knet_h->recv_from_links_buf->kf_data,
					len,
					knet_h->recv_from_links_buf->kf_node,
					dst_host_ids,
					&dst_host_ids_entries);
			if (bcast < 0) {
				log_debug(knet_h, KNET_SUB_LINK_T, "Error from dst_host_filter_fn: %d", bcast);
				goto exit_unlock;
			}

			if ((!bcast) && (!dst_host_ids_entries)) {
				log_debug(knet_h, KNET_SUB_LINK_T, "Message is unicast but no dst_host_ids_entries");
				goto exit_unlock;
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
					goto exit_unlock;
				}
			}
		}

		if (!_should_deliver(src_host, bcast, knet_h->recv_from_links_buf->kf_seq_num)) {
			if (src_host->link_handler_policy != KNET_LINK_POLICY_ACTIVE) {
				log_debug(knet_h, KNET_SUB_LINK_T, "Packet has already been delivered");
			}
			goto exit_unlock;
		}

		if (write(knet_h->sockfd,
			  knet_h->recv_from_links_buf->kf_data,
			  len - (KNET_FRAME_SIZE + sizeof(seq_num_t))) == len - (KNET_FRAME_SIZE + sizeof(seq_num_t))) {
			_has_been_delivered(src_host, bcast, knet_h->recv_from_links_buf->kf_seq_num);
		} else {
			log_debug(knet_h, KNET_SUB_LINK_T, "Packet has not been delivered");
		}

		break;
	case KNET_FRAME_PING:
		outlen = KNET_PING_SIZE;
		knet_h->recv_from_links_buf->kf_type = KNET_FRAME_PONG;
		knet_h->recv_from_links_buf->kf_node = htons(knet_h->host_id);

		if (knet_h->crypto_instance) {
			if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)knet_h->recv_from_links_buf,
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
	case KNET_FRAME_PONG:
		clock_gettime(CLOCK_MONOTONIC, &src_link->status.pong_last);

		memcpy(&recvtime, &knet_h->recv_from_links_buf->kf_time[0], sizeof(struct timespec));
		timespec_diff(recvtime,
				src_link->status.pong_last, &latency_last);

		src_link->status.latency =
			((src_link->status.latency * src_link->latency_exp) +
			((latency_last / 1000llu) *
				(src_link->latency_fix - src_link->latency_exp))) /
					src_link->latency_fix;

		if (src_link->status.latency < src_link->pong_timeout) {
			if (!src_link->status.connected) {
				log_info(knet_h, KNET_SUB_LINK, "host: %s link: %s is up",
					 src_host->name, src_link->status.dst_ipaddr);
				_link_updown(knet_h, src_host->host_id, src_link, src_link->status.enabled, 1);
			}
		}

		break;
	case KNET_FRAME_HOST_INFO:
		knet_hinfo_data = (struct knet_hinfo_data *)knet_h->recv_from_links_buf->kf_data;
		if (!knet_hinfo_data->khd_bcast) {
			knet_hinfo_data->khd_dst_node_id = ntohs(knet_hinfo_data->khd_dst_node_id);
		}
		switch(knet_hinfo_data->khd_type) {
			case KNET_HOST_INFO_LINK_UP_DOWN:
				src_link = src_host->link +
					(knet_hinfo_data->khd_dype.link_up_down.khdt_link_id % KNET_MAX_LINK);
				/*
				 * basically if the node is coming back to life from a crash
				 * we should receive a host info where local previous status == remote current status
				 * and so we can detect that node is showing up again
				 * we need to clear cbuffers and notify the node of our status by resending our host info
				 */
				if ((src_link->remoteconnected) &&
				    (src_link->remoteconnected == knet_hinfo_data->khd_dype.link_up_down.khdt_link_status)) {
					src_link->host_info_up_sent = 0;
				}
				src_link->remoteconnected = knet_hinfo_data->khd_dype.link_up_down.khdt_link_status;
				if (!src_link->remoteconnected) {
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
				log_debug(knet_h, KNET_SUB_LINK, "host message up/down. from host: %s link: %s remote connected: %u",
					  src_host->name,
					  src_link->status.dst_ipaddr,
					  src_link->remoteconnected);
				if (_dst_cache_update(knet_h, src_host->host_id)) {
					log_debug(knet_h, KNET_SUB_LINK,
						  "Unable to update switch cache (host: %s link: %s remote connected: %u)",
						  src_host->name,
						  src_link->status.dst_ipaddr,
						  src_link->remoteconnected);
				}
				break;
			case KNET_HOST_INFO_LINK_TABLE:
				break;
			default:
				log_warn(knet_h, KNET_SUB_LINK, "Receiving unknown host info message from host %s", src_host->name);
				break;
		}
		break;
	default:
		goto exit_unlock;
	}

 exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
}

static void _clear_cbuffers(struct knet_host *host)
{
	memset(host->bcast_circular_buffer, 0, KNET_CBUFFER_SIZE);
	memset(host->ucast_circular_buffer, 0, KNET_CBUFFER_SIZE);
	host->bcast_seq_num_rx = 0;
	host->ucast_seq_num_rx = 0;
}

static void _handle_dst_link_updates(knet_handle_t knet_h)
{
	uint16_t dst_host_id;
	struct knet_host *dst_host;
	int link_idx;
	int best_priority = -1;
	int send_link_idx = 0;
	uint8_t send_link_status[KNET_MAX_LINK];
	int clear_cbuffer = 0;
	int host_has_remote = 0;

	if (read(knet_h->dstpipefd[0], &dst_host_id, sizeof(dst_host_id)) != sizeof(dst_host_id)) {
		log_debug(knet_h, KNET_SUB_SWITCH_T, "Short read on pipe");
		return;
	}

	if (pthread_rwlock_wrlock(&knet_h->list_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_SWITCH_T, "Unable to get read lock");
		return;
	}

	dst_host = knet_h->host_index[dst_host_id];
	if (!dst_host) {
		log_debug(knet_h, KNET_SUB_SWITCH_T, "Unable to find host");
		goto out_unlock;
	}

	dst_host->active_link_entries = 0;

	for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
		if (dst_host->link[link_idx].status.enabled != 1) /* link is not enabled */
			continue;
		if (dst_host->link[link_idx].remoteconnected) /* track if remote is connected */
			host_has_remote = 1;
		if (dst_host->link[link_idx].status.connected != 1) /* link is not enabled */
			continue;

		if ((!dst_host->link[link_idx].host_info_up_sent) &&
		    (!dst_host->link[link_idx].donnotremoteupdate)) {
			send_link_status[send_link_idx] = link_idx;
			send_link_idx++;
			/*
			 * detect node coming back to life and reset the buffers
			 */
			if (dst_host->link[link_idx].remoteconnected) {
				clear_cbuffer = 1;
			}
		}

		if (dst_host->link_handler_policy == KNET_LINK_POLICY_PASSIVE) {
			/* for passive we look for the only active link with higher priority */
			if (dst_host->link[link_idx].priority > best_priority) {
				dst_host->active_links[0] = link_idx;
				best_priority = dst_host->link[link_idx].priority;
			}
			dst_host->active_link_entries = 1;
		} else {
			/* for RR and ACTIVE we need to copy all available links */
			dst_host->active_links[dst_host->active_link_entries] = link_idx;
			dst_host->active_link_entries++;
		}
	}

	if (dst_host->link_handler_policy == KNET_LINK_POLICY_PASSIVE) {
		log_debug(knet_h, KNET_SUB_SWITCH_T, "host: %s (passive) best link: %s (%u)",
			  dst_host->name, dst_host->link[dst_host->active_links[0]].status.dst_ipaddr,
			  dst_host->link[dst_host->active_links[0]].priority);
	} else {
		log_debug(knet_h, KNET_SUB_SWITCH_T, "host: %s has %u active links",
			  dst_host->name, dst_host->active_link_entries);
	}

	/* no active links, we can clean the circular buffers and indexes */
	if ((!dst_host->active_link_entries) || (clear_cbuffer) || (!host_has_remote)) {
		if (!host_has_remote) {
			log_debug(knet_h, KNET_SUB_SWITCH_T, "host: %s has no active remote links", dst_host->name);
		}
		if (!dst_host->active_link_entries) {
			log_warn(knet_h, KNET_SUB_SWITCH_T, "host: %s has no active links", dst_host->name);
		}
		if (clear_cbuffer) {
			log_debug(knet_h, KNET_SUB_SWITCH_T, "host: %s is coming back to life", dst_host->name);
		}
		_clear_cbuffers(dst_host);
	}

out_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);

	if (send_link_idx) {
		int i;
		struct knet_hinfo_data knet_hinfo_data;

		knet_hinfo_data.khd_type = KNET_HOST_INFO_LINK_UP_DOWN;
		knet_hinfo_data.khd_bcast = 0;
		knet_hinfo_data.khd_dst_node_id = htons(dst_host_id);
		knet_hinfo_data.khd_dype.link_up_down.khdt_link_status = 1;

		for (i=0; i < send_link_idx; i++) {
			knet_hinfo_data.khd_dype.link_up_down.khdt_link_id = send_link_status[i];
			_send_host_info(knet_h, &knet_hinfo_data, sizeof(struct knet_hinfo_data));
			dst_host->link[send_link_status[i]].host_info_up_sent = 1;
			dst_host->link[send_link_status[i]].donnotremoteupdate = 0;
		}
	}

	return;
}

static void _handle_check_each(knet_handle_t knet_h, struct knet_host *dst_host, struct knet_link *dst_link)
{
	int len;
	ssize_t outlen = KNET_PING_SIZE;
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
		memcpy(&knet_h->pingbuf->kf_time[0], &clock_now, sizeof(struct timespec));
		knet_h->pingbuf->kf_link = dst_link->link_id;

		if (knet_h->crypto_instance) {
			if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)knet_h->pingbuf,
						    KNET_PING_SIZE,
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

		if (len == outlen) {
			dst_link->ping_last = clock_now;
		} else {
			log_debug(knet_h, KNET_SUB_HB_T, "Unable to send ping packet");
		}
	}

	if (dst_link->status.connected == 1) {
		timespec_diff(pong_last, clock_now, &diff_ping);

		if (diff_ping >= (dst_link->pong_timeout * 1000llu)) {
			log_info(knet_h, KNET_SUB_LINK, "host: %s link: %s is down",
				 dst_host->name, dst_link->status.dst_ipaddr);
			_link_updown(knet_h, dst_host->host_id, dst_link, dst_link->status.enabled, 0);
		}
	}
}

void *_handle_heartbt_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	struct knet_host *dst_host;
	int link_idx;

	/* preparing ping buffer */
	knet_h->pingbuf->kf_version = KNET_FRAME_VERSION;
	knet_h->pingbuf->kf_type = KNET_FRAME_PING;
	knet_h->pingbuf->kf_node = htons(knet_h->host_id);

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

void *_handle_tap_to_links_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];
	int i, nev;

	/* preparing data buffer */
	knet_h->tap_to_links_buf->kf_version = KNET_FRAME_VERSION;
	knet_h->tap_to_links_buf->kf_node = htons(knet_h->host_id);

	while (!knet_h->fini_in_progress) {
		nev = epoll_wait(knet_h->tap_to_links_epollfd, events, KNET_EPOLL_MAX_EVENTS, -1);

		for (i = 0; i < nev; i++) {
			if (events[i].data.fd == knet_h->sockfd) {
				knet_h->tap_to_links_buf->kf_type = KNET_FRAME_DATA;
			} else {
				knet_h->tap_to_links_buf->kf_type = KNET_FRAME_HOST_INFO;
			}
			_handle_tap_to_links(knet_h, events[i].data.fd);
		}
	}

	return NULL;

}

void *_handle_recv_from_links_thread(void *data)
{
	int i, nev;
	knet_handle_t knet_h = (knet_handle_t) data;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];

	while (!knet_h->fini_in_progress) {
		nev = epoll_wait(knet_h->recv_from_links_epollfd, events, KNET_EPOLL_MAX_EVENTS, -1);

		for (i = 0; i < nev; i++) {
			_handle_recv_from_links(knet_h, events[i].data.fd);
		}
	}

	return NULL;
}

void *_handle_dst_link_handler_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];

	while (!knet_h->fini_in_progress) {
		if (epoll_wait(knet_h->dst_link_handler_epollfd, events, KNET_EPOLL_MAX_EVENTS, -1) >= 1)
			_handle_dst_link_updates(knet_h);
	}

	return NULL;
}
