/*
 * Copyright (C) 2010-2025 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>

#include "host.h"
#include "internals.h"
#include "logging.h"
#include "threads_common.h"

static void _host_list_update(knet_handle_t knet_h)
{
	struct knet_host *host;
	knet_h->host_ids_entries = 0;

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		knet_h->host_ids[knet_h->host_ids_entries] = host->host_id;
		knet_h->host_ids_entries++;
	}
}

int knet_host_add(knet_handle_t knet_h, knet_node_id_t host_id)
{
	int savederrno = 0, err = 0;
	struct knet_host *host = NULL;
	uint8_t link_idx;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (knet_h->host_index[host_id]) {
		err = -1;
		savederrno = EEXIST;
		log_err(knet_h, KNET_SUB_HOST, "Unable to add host %u: %s",
			  host_id, strerror(savederrno));
		goto exit_unlock;
	}

	host = malloc(sizeof(struct knet_host));
	if (!host) {
		err = -1;
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HOST, "Unable to allocate memory for host %u: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	memset(host, 0, sizeof(struct knet_host));

	host->defrag_bufs = malloc(knet_h->defrag_bufs_min * sizeof(struct knet_host_defrag_buf));
	if (!host->defrag_bufs) {
		err = -1;
		savederrno = errno;
		log_err(knet_h, KNET_SUB_HOST, "Unable to allocate memory for host %u defrag buffers: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	host->allocated_defrag_bufs = knet_h->defrag_bufs_min;

	memset(host->defrag_bufs, 0, host->allocated_defrag_bufs * sizeof(struct knet_host_defrag_buf));

	log_debug(knet_h, KNET_SUB_HOST, "Allocated %u defrag buffers for host %u",
		  host->allocated_defrag_bufs, host_id);

	/*
	 * set host_id
	 */
	host->host_id = host_id;

	/*
	 * fill up our own data
	 */

	if (knet_h->host_id == host->host_id) {
		host->onwire_ver = knet_h->onwire_ver;
		host->onwire_max_ver = knet_h->onwire_max_ver;
	}

	/*
	 * set default host->name to host_id for logging
	 */
	snprintf(host->name, KNET_MAX_HOST_LEN, "%u", host_id);

	/*
	 * initialize links internal data
	 */
	for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
		host->link[link_idx].link_id = link_idx;
		host->link[link_idx].status.stats.latency_min = UINT32_MAX;
	}

	/*
	 * add new host to the index
	 */
	knet_h->host_index[host_id] = host;

	/*
	 * add new host to host list
	 */
	if (knet_h->host_head) {
		host->next = knet_h->host_head;
	}
	knet_h->host_head = host;

	_host_list_update(knet_h);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	if (err < 0) {
		if (host) {
			free(host->defrag_bufs);
		}
		free(host);
	}
	errno = err ? savederrno : 0;
	return err;
}

int knet_host_remove(knet_handle_t knet_h, knet_node_id_t host_id)
{
	int savederrno = 0, err = 0;
	struct knet_host *host, *removed;
	uint8_t link_idx;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	host = knet_h->host_index[host_id];

	if (!host) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Unable to remove host %u: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	/*
	 * if links are configured we cannot release the host
	 */

	for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
		if (host->link[link_idx].configured) {
			err = -1;
			savederrno = EBUSY;
			log_err(knet_h, KNET_SUB_HOST, "Unable to remove host %u, links are still configured: %s",
				host_id, strerror(savederrno));
			goto exit_unlock;
		}
	}

	removed = NULL;

	/*
	 * removing host from list
	 */
	// coverity[NULL_FIELD:SUPPRESS] - host_head is not going to be NULL
	if (knet_h->host_head->host_id == host_id) {
		// coverity[NULL_FIELD:SUPPRESS] - host_head is not going to be NULL
		removed = knet_h->host_head;
		// coverity[NULL_FIELD:SUPPRESS] - host_head is not going to be NULL
		knet_h->host_head = removed->next;
	} else {
		for (host = knet_h->host_head; host->next != NULL; host = host->next) {
			if (host->next->host_id == host_id) {
				removed = host->next;
				host->next = removed->next;
				break;
			}
		}
	}

	knet_h->host_index[host_id] = NULL;

	if (removed) {
		free(removed->defrag_bufs);
	}
	free(removed);

	_host_list_update(knet_h);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_host_set_name(knet_handle_t knet_h, knet_node_id_t host_id, const char *name)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!knet_h->host_index[host_id]) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Unable to find host %u to set name: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	if (!name) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Unable to set name for host %u: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	if (strlen(name) >= KNET_MAX_HOST_LEN) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Requested name for host %u is too long: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		if (!strncmp(host->name, name, KNET_MAX_HOST_LEN)) {
			err = -1;
			savederrno = EEXIST;
			log_err(knet_h, KNET_SUB_HOST, "Duplicated name found on host_id %u",
				host->host_id);
			goto exit_unlock;
		}
	}

	snprintf(knet_h->host_index[host_id]->name, KNET_MAX_HOST_LEN, "%s", name);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_host_get_name_by_host_id(knet_handle_t knet_h, knet_node_id_t host_id,
				  char *name)
{
	int savederrno = 0, err = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if (!name) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!knet_h->host_index[host_id]) {
		savederrno = EINVAL;
		err = -1;
		log_debug(knet_h, KNET_SUB_HOST, "Host %u not found", host_id);
		goto exit_unlock;
	}

	snprintf(name, KNET_MAX_HOST_LEN, "%s", knet_h->host_index[host_id]->name);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_host_get_id_by_host_name(knet_handle_t knet_h, const char *name,
				  knet_node_id_t *host_id)
{
	int savederrno = 0, err = 0, found = 0;
	struct knet_host *host;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if (!name) {
		errno = EINVAL;
		return -1;
	}

	if (!host_id) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		if (!strncmp(name, host->name, KNET_MAX_HOST_LEN)) {
			found = 1;
			*host_id = host->host_id;
			break;
		}
	}

	if (!found) {
		savederrno = ENOENT;
		err = -1;
	}

	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_host_get_host_list(knet_handle_t knet_h,
			    knet_node_id_t *host_ids, size_t *host_ids_entries)
{
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if ((!host_ids) || (!host_ids_entries)) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	memmove(host_ids, knet_h->host_ids, sizeof(knet_h->host_ids));
	*host_ids_entries = knet_h->host_ids_entries;

	pthread_rwlock_unlock(&knet_h->global_rwlock);
	return 0;
}

int knet_host_set_policy(knet_handle_t knet_h, knet_node_id_t host_id,
			 uint8_t policy)
{
	int savederrno = 0, err = 0;
	uint8_t old_policy;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if (policy > KNET_LINK_POLICY_RR) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!knet_h->host_index[host_id]) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Unable to set name for host %u: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	old_policy = knet_h->host_index[host_id]->link_handler_policy;
	knet_h->host_index[host_id]->link_handler_policy = policy;

	if (_host_dstcache_update_async(knet_h, knet_h->host_index[host_id])) {
		savederrno = errno;
		err = -1;
		knet_h->host_index[host_id]->link_handler_policy = old_policy;
		log_debug(knet_h, KNET_SUB_HOST, "Unable to update switch cache for host %u: %s",
			  host_id, strerror(savederrno));
	}

	log_debug(knet_h, KNET_SUB_HOST, "Host %u has new switching policy: %u", host_id, policy);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_host_get_policy(knet_handle_t knet_h, knet_node_id_t host_id,
			 uint8_t *policy)
{
	int savederrno = 0, err = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if (!policy) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!knet_h->host_index[host_id]) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Unable to get name for host %u: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	*policy = knet_h->host_index[host_id]->link_handler_policy;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_host_get_status(knet_handle_t knet_h, knet_node_id_t host_id,
			 struct knet_host_status *status)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if (!status) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	host = knet_h->host_index[host_id];
	if (!host) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Unable to find host %u: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	memmove(status, &host->status, sizeof(struct knet_host_status));

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_host_enable_status_change_notify(knet_handle_t knet_h,
					  void *host_status_change_notify_fn_private_data,
					  void (*host_status_change_notify_fn) (
						void *private_data,
						knet_node_id_t host_id,
						uint8_t reachable,
						uint8_t remote,
						uint8_t external))
{
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	knet_h->host_status_change_notify_fn_private_data = host_status_change_notify_fn_private_data;
	knet_h->host_status_change_notify_fn = host_status_change_notify_fn;
	if (knet_h->host_status_change_notify_fn) {
		log_debug(knet_h, KNET_SUB_HOST, "host_status_change_notify_fn enabled");
	} else {
		log_debug(knet_h, KNET_SUB_HOST, "host_status_change_notify_fn disabled");
	}

	pthread_rwlock_unlock(&knet_h->global_rwlock);

	errno = 0;
	return 0;
}

void _clear_defrag_bufs_stats(struct knet_host *host)
{
	memset(&host->in_use_defrag_buffers, 0, sizeof(host->in_use_defrag_buffers));
	host->in_use_defrag_buffers_samples = 0;
	host->in_use_defrag_buffers_index = 0;
}

static void _clear_cbuffers(struct knet_host *host, seq_num_t rx_seq_num)
{
	int i;

	memset(host->circular_buffer, 0, KNET_CBUFFER_SIZE);
	host->rx_seq_num = rx_seq_num;

	memset(host->circular_buffer_defrag, 0, KNET_CBUFFER_SIZE);

	for (i = 0; i < host->allocated_defrag_bufs; i++) {
		memset(&host->defrag_bufs[i], 0, sizeof(struct knet_host_defrag_buf));
	}
	_clear_defrag_bufs_stats(host);
}

static void _reclaim_old_defrag_bufs(knet_handle_t knet_h, struct knet_host *host, seq_num_t seq_num)
{
	seq_num_t head, tail; /* seq_num boundaries */
	int i;

	head = seq_num + 1;
	if (knet_h->defrag_bufs_max > host->allocated_defrag_bufs) {
		tail = seq_num - (knet_h->defrag_bufs_max + 1);
	} else {
		tail = seq_num - (host->allocated_defrag_bufs + 1);
	}

	/*
	 * expire old defrag buffers
	 */
	for (i = 0; i < host->allocated_defrag_bufs; i++) {
		if (host->defrag_bufs[i].in_use) {
			/*
			 * head has done a rollover to 0+
			 */
			if (tail > head) {
				if ((host->defrag_bufs[i].pckt_seq >= head) && (host->defrag_bufs[i].pckt_seq <= tail)) {
					host->defrag_bufs[i].in_use = 0;
				}
			} else {
				if ((host->defrag_bufs[i].pckt_seq >= head) || (host->defrag_bufs[i].pckt_seq <= tail)){
					host->defrag_bufs[i].in_use = 0;
				}
			}
		}
	}
}

/*
 * check if a given packet seq num is in the circular buffers
 * defrag_buf = 0 -> use normal cbuf 1 -> use the defrag buffer lookup
 */

int _seq_num_lookup(knet_handle_t knet_h, struct knet_host *host, seq_num_t seq_num, int defrag_buf, int clear_buf)
{
	size_t head, tail; /* circular buffer indexes */
	seq_num_t seq_dist;
	char *dst_cbuf = host->circular_buffer;
	char *dst_cbuf_defrag = host->circular_buffer_defrag;
	seq_num_t *dst_seq_num = &host->rx_seq_num;

	/*
	 * There is a potential race condition where the sender
	 * is overloaded, sending data packets before pings
	 * can kick in and set the correct dst_seq_num.
	 *
	 * if this node is starting up (dst_seq_num = 0),
	 * it can start rejecing valid packets and get stuck.
	 *
	 * Set the dst_seq_num to the first seen packet and
	 * use that as reference instead.
	 */
	if (!*dst_seq_num) {
		*dst_seq_num = seq_num;
	}

	if (clear_buf) {
		_clear_cbuffers(host, seq_num);
	}

	_reclaim_old_defrag_bufs(knet_h, host, *dst_seq_num);

	if (seq_num < *dst_seq_num) {
		seq_dist =  (SEQ_MAX - seq_num) + *dst_seq_num;
	} else {
		seq_dist = *dst_seq_num - seq_num;
	}

	head = seq_num % KNET_CBUFFER_SIZE;

	if (seq_dist < KNET_CBUFFER_SIZE) { /* seq num is in ring buffer */
		if (!defrag_buf) {
			return (dst_cbuf[head] == 0) ? 1 : 0;
		} else {
			return (dst_cbuf_defrag[head] == 0) ? 1 : 0;
		}
	} else if (seq_dist <= SEQ_MAX - KNET_CBUFFER_SIZE) {
		memset(dst_cbuf, 0, KNET_CBUFFER_SIZE);
		memset(dst_cbuf_defrag, 0, KNET_CBUFFER_SIZE);
		*dst_seq_num = seq_num;
	}

	/* cleaning up circular buffer */
	tail = (*dst_seq_num + 1) % KNET_CBUFFER_SIZE;

	if (tail > head) {
		memset(dst_cbuf + tail, 0, KNET_CBUFFER_SIZE - tail);
		memset(dst_cbuf, 0, head + 1);
		memset(dst_cbuf_defrag + tail, 0, KNET_CBUFFER_SIZE - tail);
		memset(dst_cbuf_defrag, 0, head + 1);
	} else {
		memset(dst_cbuf + tail, 0, head - tail + 1);
		memset(dst_cbuf_defrag + tail, 0, head - tail + 1);
	}

	*dst_seq_num = seq_num;

	return 1;
}

void _seq_num_set(struct knet_host *host, seq_num_t seq_num, int defrag_buf)
{
	if (!defrag_buf) { 
		host->circular_buffer[seq_num % KNET_CBUFFER_SIZE] = 1;
	} else {
		host->circular_buffer_defrag[seq_num % KNET_CBUFFER_SIZE] = 1;
	}

	return;
}

int _host_dstcache_update_async(knet_handle_t knet_h, struct knet_host *host)
{
	int savederrno = 0;
	knet_node_id_t host_id = host->host_id;

	if (sendto(knet_h->dstsockfd[1], &host_id, sizeof(host_id), MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0) != sizeof(host_id)) {
		savederrno = errno;
		log_debug(knet_h, KNET_SUB_HOST, "Unable to write to dstpipefd[1]: %s",
			  strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	return 0;
}

int _host_dstcache_update_sync(knet_handle_t knet_h, struct knet_host *host)
{
	int link_idx;
	int best_priority = -1;
	int reachable = 0;

	if (knet_h->host_id == host->host_id && knet_h->has_loop_link) {
		host->active_link_entries = 1;
		return 0;
	}

	host->active_link_entries = 0;
	for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
		if (host->link[link_idx].status.enabled != 1) /* link is not enabled */
			continue;
		if (host->link[link_idx].status.connected != 1) /* link is not enabled */
			continue;
		if (host->link[link_idx].has_valid_mtu != 1) /* link does not have valid MTU */
			continue;

		if (host->link_handler_policy == KNET_LINK_POLICY_PASSIVE) {
			/* for passive we look for the only active link with higher priority */
			if (host->link[link_idx].priority > best_priority) {
				host->active_links[0] = link_idx;
				best_priority = host->link[link_idx].priority;
			}
			host->active_link_entries = 1;
		} else {
			/* for RR and ACTIVE we need to copy all available links */
			host->active_links[host->active_link_entries] = link_idx;
			host->active_link_entries++;
		}
	}

	if (host->link_handler_policy == KNET_LINK_POLICY_PASSIVE) {
		log_info(knet_h, KNET_SUB_HOST, "host: %u (passive) best link: %u (pri: %u)",
			 host->host_id, host->link[host->active_links[0]].link_id,
			 host->link[host->active_links[0]].priority);
	} else {
		log_info(knet_h, KNET_SUB_HOST, "host: %u has %u active links",
			 host->host_id, host->active_link_entries);
	}

	/* no active links, we can clean the circular buffers and indexes */
	if (!host->active_link_entries) {
		log_warn(knet_h, KNET_SUB_HOST, "host: %u has no active links", host->host_id);
		_clear_cbuffers(host, 0);
	} else {
		reachable = 1;
	}

	if (host->status.reachable != reachable) {
		host->status.reachable = reachable;
		if (knet_h->host_status_change_notify_fn) {
			knet_h->host_status_change_notify_fn(
						     knet_h->host_status_change_notify_fn_private_data,
						     host->host_id,
						     host->status.reachable,
						     host->status.remote,
						     host->status.external);
		}
	}

	return 0;
}

void _handle_onwire_version(knet_handle_t knet_h, struct knet_host *host, struct knet_header *inbuf)
{
	struct knet_host *tmp_host = NULL;
	uint8_t onwire_ver = knet_h->onwire_max_ver;
	int docallback = 0;

	/*
	 * data we process here are onwire independent
	 * we are in a global read only lock context, so it´s safe to parse host lists
	 * and we can change onwire_ver using the dedicated mutex
	 */

	/*
	 * update current host onwire info
	 */
	host->onwire_ver = inbuf->kh_version;
	host->onwire_max_ver = inbuf->kh_max_ver;

	for (tmp_host = knet_h->host_head; tmp_host != NULL; tmp_host = tmp_host->next) {
		/*
		 * do not attempt to change protocol till
		 * we see all nodes at least once.
		 */
		if (!tmp_host->onwire_max_ver) {
			return;
		}

		/*
		 * ignore nodes were max ver is lower than our min ver
		 * logged as error by thread_rx, we need to make sure to skip it
		 * during onwire_ver calculation.
		 */
		if (tmp_host->onwire_max_ver < knet_h->onwire_min_ver) {
			continue;
		}

		/*
		 * use the highest max_ver common to all known nodes
		 */
		if (tmp_host->onwire_max_ver < onwire_ver) {
			onwire_ver = tmp_host->onwire_max_ver;
		}
	}

	if (pthread_mutex_lock(&knet_h->onwire_mutex)) {
		log_debug(knet_h, KNET_SUB_HOST, "Unable to get onwire mutex lock");
		return;
	}

	if (knet_h->onwire_force_ver) {
		onwire_ver = knet_h->onwire_force_ver;
	}

	if (knet_h->onwire_ver != onwire_ver) {
		log_debug(knet_h, KNET_SUB_HOST, "node %u updating onwire version to %u", knet_h->host_id, onwire_ver);
		knet_h->onwire_ver = onwire_ver;
		docallback = 1;
	}

	pthread_mutex_unlock(&knet_h->onwire_mutex);

	/*
	 * do the callback outside of locked context and use cached value
	 * to avoid blocking on locking
	 */
	if ((docallback) &&
	    (knet_h->onwire_ver_notify_fn)) {
		knet_h->onwire_ver_notify_fn(knet_h->onwire_ver_notify_fn_private_data,
					     knet_h->onwire_min_ver,
					     knet_h->onwire_max_ver,
					     onwire_ver);
	}
}
