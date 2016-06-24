/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

#include "host.h"
#include "internals.h"
#include "logging.h"

static void _host_list_update(knet_handle_t knet_h)
{
	struct knet_host *host;
	knet_h->host_ids_entries = 0;

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		knet_h->host_ids[knet_h->host_ids_entries] = host->host_id;
		knet_h->host_ids_entries++;
	}
}

int knet_host_add(knet_handle_t knet_h, uint16_t host_id)
{
	int savederrno = 0, err = 0;
	struct knet_host *host = NULL;
	uint8_t link_idx;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->global_rwlock);
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

	/*
	 * set host_id
	 */
	host->host_id = host_id;

	/*
	 * set default host->name to host_id for logging
	 */
	snprintf(host->name, KNET_MAX_HOST_LEN - 1, "%u", host_id);

	/*
	 * initialize links internal data
	 */
	for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
		host->link[link_idx].link_id = link_idx;
	}

	/*
	 * Use this mutex to protect active_links updates without
	 * using a global rw lock
	 */
	savederrno = pthread_mutex_init(&host->active_links_mutex, NULL);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to initialize active links mutex: %s",
			strerror(savederrno));
		err = -1;
		goto exit_unlock;
	}

	/*
	 * add new host to the index
	 */
	knet_h->host_index[host_id] = host;

	/*
	 * add new host to host list
	 */
	if (!knet_h->host_head) {
		knet_h->host_head = host;
		knet_h->host_tail = host;
	} else {
		knet_h->host_tail->next = host;
		knet_h->host_tail = host;
	}

	_host_list_update(knet_h);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	if (err < 0) {
		free(host);
	}
	errno = savederrno;
	return err;
}

int knet_host_remove(knet_handle_t knet_h, uint16_t host_id)
{
	int savederrno = 0, err = 0;
	struct knet_host *host, *removed;
	uint8_t link_idx;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->global_rwlock);
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
		if (host->link[link_idx].status.enabled) {
			err = -1;
			savederrno = EBUSY;
			log_err(knet_h, KNET_SUB_HOST, "Unable to remove host %u, links are still configured: %s",
				host_id, strerror(savederrno));
			goto exit_unlock;
		}
	}

	pthread_mutex_destroy(&host->active_links_mutex);

	removed = NULL;

	/*
	 * removing host from list
	 */
	if (knet_h->host_head->host_id == host_id) {
		removed = knet_h->host_head;
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
	free(removed);

	_host_list_update(knet_h);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_host_set_name(knet_handle_t knet_h, uint16_t host_id, const char *name)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->global_rwlock);
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
		if (!strncmp(host->name, name, KNET_MAX_HOST_LEN - 1)) {
			err = -1;
			savederrno = EEXIST;
			log_err(knet_h, KNET_SUB_HOST, "Duplicated name found on host_id %u",
				host->host_id);
			goto exit_unlock;
		}
	}

	snprintf(knet_h->host_index[host_id]->name, KNET_MAX_HOST_LEN - 1, "%s", name);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_host_get_name_by_host_id(knet_handle_t knet_h, uint16_t host_id,
				  char *name)
{
	int savederrno = 0, err = 0;

	if (!knet_h) {
		errno = EINVAL;
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

	snprintf(name, KNET_MAX_HOST_LEN - 1, "%s", knet_h->host_index[host_id]->name);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_host_get_id_by_host_name(knet_handle_t knet_h, const char *name,
				  uint16_t *host_id)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;

	if (!knet_h) {
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

	if (!name) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Unable to get id for unknown host: %s",
			strerror(savederrno));
		goto exit_unlock;
	}

	if (!host_id) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Unable to get id for host %s: %s",
			name, strerror(savederrno));
		goto exit_unlock;
	}

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		if (!strcmp(name, host->name)) {
			*host_id = host->host_id;
			err = 1;
			break;
		}
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_host_get_host_list(knet_handle_t knet_h,
			    uint16_t *host_ids, size_t *host_ids_entries)
{
	int savederrno = 0, err = 0;

	if (!knet_h) {
		errno = EINVAL;
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
	errno = savederrno;
	return err;
}

int knet_host_set_policy(knet_handle_t knet_h, uint16_t host_id,
			 int policy)
{
	int savederrno = 0, err = 0;
	int old_policy;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->global_rwlock);
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

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_host_get_policy(knet_handle_t knet_h, uint16_t host_id,
			 int *policy)
{
	int savederrno = 0, err = 0;

	if (!knet_h) {
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

	if ((!knet_h->host_index[host_id]) || (!policy)) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Unable to get name for host %u: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	*policy = knet_h->host_index[host_id]->link_handler_policy;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_host_get_status(knet_handle_t knet_h, uint16_t host_id,
			 struct knet_host_status *status)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;

	if (!knet_h) {
		errno = EINVAL;
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
	errno = savederrno;
	return err;
}

int knet_host_enable_status_change_notify(knet_handle_t knet_h,
					  void *host_status_change_notify_fn_private_data,
					  void (*host_status_change_notify_fn) (
						void *private_data,
						uint16_t host_id,
						uint8_t reachable,
						uint8_t remote,
						uint8_t external))
{
	int savederrno = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->global_rwlock);
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

	return 0;
}

int _send_host_info(knet_handle_t knet_h, const void *data, const size_t datalen)
{
	/*
	 * access here is protected by calling functions
	 */
	if (knet_h->fini_in_progress) {
		return 0;
	}

	if (pthread_rwlock_wrlock(&knet_h->host_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_HOST, "Unable to get write lock");
		return -1;
	}

	if (pthread_mutex_lock(&knet_h->host_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_HOST, "Unable to get mutex lock");
		pthread_rwlock_unlock(&knet_h->host_rwlock);
		return -1;
	}

	if (sendto(knet_h->hostsockfd[1], data, datalen, MSG_DONTWAIT, NULL, 0) != datalen) {
		log_debug(knet_h, KNET_SUB_HOST, "Unable to write data to hostpipe");
		pthread_mutex_unlock(&knet_h->host_mutex);
		pthread_rwlock_unlock(&knet_h->host_rwlock);
		return -1;
	}

	pthread_cond_wait(&knet_h->host_cond, &knet_h->host_mutex);
	pthread_mutex_unlock(&knet_h->host_mutex);
	pthread_rwlock_unlock(&knet_h->host_rwlock);

	return 0;
}

/*
 * check if a given packet seq num is in the circular buffers
 * bcast = 0 -> unicast packet | 1 -> broadcast|mcast
 * defrag_buf = 0 -> use normal cbuf 1 -> use the defrag buffer lookup
 */

int _seq_num_lookup(struct knet_host *host, int bcast, seq_num_t seq_num, int defrag_buf)
{
	size_t i, j; /* circular buffer indexes */
	seq_num_t seq_dist;
	char *dst_cbuf = NULL;
	char *dst_cbuf_defrag = NULL;
	seq_num_t *dst_seq_num;

	if (bcast) {
		dst_cbuf = host->bcast_circular_buffer;
		dst_cbuf_defrag = host->bcast_circular_buffer_defrag;
		dst_seq_num = &host->bcast_seq_num_rx;
	} else {
		dst_cbuf = host->ucast_circular_buffer;
		dst_cbuf_defrag = host->ucast_circular_buffer_defrag;
		dst_seq_num = &host->ucast_seq_num_rx;
	}

	if (seq_num < *dst_seq_num) {
		seq_dist =  (SEQ_MAX - seq_num) + *dst_seq_num;
	} else {
		seq_dist = *dst_seq_num - seq_num;
	}

	j = seq_num % KNET_CBUFFER_SIZE;

	if (seq_dist < KNET_CBUFFER_SIZE) { /* seq num is in ring buffer */
		if (!defrag_buf) {
			return (dst_cbuf[j] == 0) ? 1 : 0;
		} else {
			return (dst_cbuf_defrag[j] == 0) ? 1 : 0;
		}
	} else if (seq_dist <= SEQ_MAX - KNET_CBUFFER_SIZE) {
		memset(dst_cbuf, 0, KNET_CBUFFER_SIZE);
		memset(dst_cbuf_defrag, 0, KNET_CBUFFER_SIZE);
		*dst_seq_num = seq_num;
	}

	/* cleaning up circular buffer */
	i = (*dst_seq_num + 1) % KNET_CBUFFER_SIZE;

	if (i > j) {
		memset(dst_cbuf + i, 0, KNET_CBUFFER_SIZE - i);
		memset(dst_cbuf, 0, j + 1);
		memset(dst_cbuf_defrag + i, 0, KNET_CBUFFER_SIZE - i);
		memset(dst_cbuf_defrag, 0, j + 1);
	} else {
		memset(dst_cbuf + i, 0, j - i + 1);
		memset(dst_cbuf_defrag + i, 0, j - i + 1);
	}

	*dst_seq_num = seq_num;

	return 1;
}

void _seq_num_set(struct knet_host *host, int bcast, seq_num_t seq_num, int defrag_buf)
{
	if (!defrag_buf) { 
		if (bcast) {
			host->bcast_circular_buffer[seq_num % KNET_CBUFFER_SIZE] = 1;
		} else {
			host->ucast_circular_buffer[seq_num % KNET_CBUFFER_SIZE] = 1;
		}
	} else {
		if (bcast) {
			host->bcast_circular_buffer_defrag[seq_num % KNET_CBUFFER_SIZE] = 1;
		} else {
			host->ucast_circular_buffer_defrag[seq_num % KNET_CBUFFER_SIZE] = 1;
		}
	}

	return;
}

int _host_dstcache_update_async(knet_handle_t knet_h, struct knet_host *host)
{
	int savederrno = 0;
	uint16_t host_id = host->host_id;

	if (sendto(knet_h->dstsockfd[1], &host_id, sizeof(host_id), MSG_DONTWAIT, NULL, 0) != sizeof(host_id)) {
		savederrno = errno;
		log_debug(knet_h, KNET_SUB_HOST, "Unable to write to dstpipefd[1]: %s",
			  strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	return 0;
}

static void _clear_cbuffers(struct knet_host *host)
{
	int i;

	memset(host->bcast_circular_buffer, 0, KNET_CBUFFER_SIZE);
	memset(host->ucast_circular_buffer, 0, KNET_CBUFFER_SIZE);
	host->bcast_seq_num_rx = 0;
	host->ucast_seq_num_rx = 0;

	memset(host->bcast_circular_buffer_defrag, 0, KNET_CBUFFER_SIZE);
	memset(host->ucast_circular_buffer_defrag, 0, KNET_CBUFFER_SIZE);

	for (i = 0; i < KNET_MAX_LINK; i++) {
		memset(&host->defrag_buf[i], 0, sizeof(struct knet_host_defrag_buf));
	}
}

int _host_dstcache_update_sync(knet_handle_t knet_h, struct knet_host *host)
{
	int link_idx;
	int best_priority = -1;
	int send_link_idx = 0;
	uint8_t send_link_status[KNET_MAX_LINK];
	int clear_cbuffer = 0;
	int host_has_remote = 0;
	int reachable = 0;

	if (pthread_mutex_lock(&host->active_links_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_HOST, "Unable to get active links mutex!");
		return -1;
	}

	host->active_link_entries = 0;

	for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
		if (host->link[link_idx].status.enabled != 1) /* link is not enabled */
			continue;
		if (host->link[link_idx].remoteconnected == KNET_HOSTINFO_LINK_STATUS_UP) /* track if remote is connected */
			host_has_remote = 1;
		if (host->link[link_idx].status.connected != 1) /* link is not enabled */
			continue;
		if (host->link[link_idx].has_valid_mtu != 1) /* link does not have valid MTU */
			continue;

		if ((!host->link[link_idx].host_info_up_sent) &&
		    (!host->link[link_idx].donnotremoteupdate)) {
			send_link_status[send_link_idx] = link_idx;
			send_link_idx++;
			/*
			 * detect node coming back to life and reset the buffers
			 */
			if (host->link[link_idx].remoteconnected == KNET_HOSTINFO_LINK_STATUS_UP) {
				clear_cbuffer = 1;
			}
		}

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
		log_debug(knet_h, KNET_SUB_HOST, "host: %u (passive) best link: %u (pri: %u)",
			  host->host_id, host->link[host->active_links[0]].link_id,
			  host->link[host->active_links[0]].priority);
	} else {
		log_debug(knet_h, KNET_SUB_HOST, "host: %u has %u active links",
			  host->host_id, host->active_link_entries);
	}

	/* no active links, we can clean the circular buffers and indexes */
	if ((!host->active_link_entries) || (clear_cbuffer) || (!host_has_remote)) {
		if (!host_has_remote) {
			log_debug(knet_h, KNET_SUB_HOST, "host: %u has no active remote links", host->host_id);
		}
		if (!host->active_link_entries) {
			log_warn(knet_h, KNET_SUB_HOST, "host: %u has no active links", host->host_id);
		}
		if (clear_cbuffer) {
			log_debug(knet_h, KNET_SUB_HOST, "host: %u is coming back to life", host->host_id);
		}
		_clear_cbuffers(host);
	}

	pthread_mutex_unlock(&host->active_links_mutex);

	if (send_link_idx) {
		int i;
		struct knet_hostinfo knet_hostinfo;

		knet_hostinfo.khi_type = KNET_HOSTINFO_TYPE_LINK_UP_DOWN;
		knet_hostinfo.khi_bcast = KNET_HOSTINFO_UCAST;
		knet_hostinfo.khi_dst_node_id = host->host_id;
		knet_hostinfo.khip_link_status_status = KNET_HOSTINFO_LINK_STATUS_UP;

		for (i=0; i < send_link_idx; i++) {
			knet_hostinfo.khip_link_status_link_id = send_link_status[i];
			_send_host_info(knet_h, &knet_hostinfo, KNET_HOSTINFO_LINK_STATUS_SIZE);
			host->link[send_link_status[i]].host_info_up_sent = 1;
			host->link[send_link_status[i]].donnotremoteupdate = 0;
		}
	}

	if (host->active_link_entries) {
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
