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
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

#include "host.h"
#include "internals.h"
#include "logging.h"

int knet_host_add(knet_handle_t knet_h, uint16_t host_id)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;
	uint8_t link_idx;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->list_rwlock);
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

exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
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

	savederrno = pthread_rwlock_wrlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!knet_h->host_index[host_id]) {
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
		if (knet_h->host_index[host_id]->link[link_idx].status.configured) {
			err = -1;
			savederrno = EBUSY;
			log_err(knet_h, KNET_SUB_HOST, "Unable to remove host %u, links are still configuerd: %s",
				host_id, strerror(savederrno));
			goto exit_unlock;
		}
	}

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

exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
	errno = savederrno;
	return err;
}

int knet_host_set_name(knet_handle_t knet_h, uint16_t host_id, const char *name)
{
	int savederrno = 0, err = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->list_rwlock);
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

	snprintf(knet_h->host_index[host_id]->name, KNET_MAX_HOST_LEN - 1, "%s", name);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
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

	savederrno = pthread_rwlock_rdlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!name) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Unable to get name for host %u: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	if (!knet_h->host_index[host_id]) {
		log_debug(knet_h, KNET_SUB_HOST, "Host %u not found", host_id);
		goto exit_unlock;
	}

	snprintf(name, KNET_MAX_HOST_LEN - 1, "%s", knet_h->host_index[host_id]->name);
	err = 1;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
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

	savederrno = pthread_rwlock_rdlock(&knet_h->list_rwlock);
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
	pthread_rwlock_unlock(&knet_h->list_rwlock);
	errno = savederrno;
	return err;
}

int knet_host_get_host_list(knet_handle_t knet_h,
			    uint16_t *host_ids, size_t *host_ids_entries)
{
	int savederrno = 0, err = 0, entries = 0;
	struct knet_host *host;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HOST, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if ((!host_ids) || (!host_ids_entries)) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HOST, "Unable to get host list: %s",
			strerror(savederrno));
		goto exit_unlock;
	}

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		host_ids[entries] = host->host_id;
		entries++;
	}

	*host_ids_entries = entries;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
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

	savederrno = pthread_rwlock_wrlock(&knet_h->list_rwlock);
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

	if (_dst_cache_update(knet_h, host_id)) {
		savederrno = errno;
		err = -1;
		knet_h->host_index[host_id]->link_handler_policy = old_policy;
		log_debug(knet_h, KNET_SUB_HOST, "Unable to update switch cache for host %u: %s",
			  host_id, strerror(savederrno));
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
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

	savederrno = pthread_rwlock_rdlock(&knet_h->list_rwlock);
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
	pthread_rwlock_unlock(&knet_h->list_rwlock);
	errno = savederrno;
	return err;
}

int _send_host_info(knet_handle_t knet_h, const void *data, const size_t datalen)
{
	size_t byte_cnt = 0;
	int len;

	if (pthread_rwlock_wrlock(&knet_h->host_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_HOST, "Unable to get write lock");
		return -1;
	}

	if (pthread_mutex_lock(&knet_h->host_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_HOST, "Unable to get mutex lock");
		pthread_rwlock_unlock(&knet_h->host_rwlock);
		return -1;
	}

	while (byte_cnt < datalen) {
		len = write(knet_h->hostpipefd[1], data, datalen - byte_cnt);
		if (len <= 0) {
			log_debug(knet_h, KNET_SUB_HOST, "Unable to write data to hostpipe");
			pthread_mutex_unlock(&knet_h->host_mutex);
			pthread_rwlock_unlock(&knet_h->host_rwlock);
			return -1;
		}

		byte_cnt += len;
	}

	pthread_cond_wait(&knet_h->host_cond, &knet_h->host_mutex);
	pthread_mutex_unlock(&knet_h->host_mutex);
	pthread_rwlock_unlock(&knet_h->host_rwlock);

	return 0;
}

/* bcast = 0 -> unicast packet | 1 -> broadcast|mcast */

/* make this bcast/ucast aware */
int _should_deliver(struct knet_host *host, int bcast, seq_num_t seq_num)
{
	size_t i, j; /* circular buffer indexes */
	seq_num_t seq_dist;
	char *dst_cbuf = NULL;
	seq_num_t *dst_seq_num;

	if (bcast) {
		dst_cbuf = host->bcast_circular_buffer;
		dst_seq_num = &host->bcast_seq_num_rx;
	} else {
		dst_cbuf = host->ucast_circular_buffer;
		dst_seq_num = &host->ucast_seq_num_rx;
	}

	seq_dist = (seq_num < *dst_seq_num) ?
		(SEQ_MAX - seq_num) + *dst_seq_num : *dst_seq_num - seq_num;

	j = seq_num % KNET_CBUFFER_SIZE;

	if (seq_dist < KNET_CBUFFER_SIZE) { /* seq num is in ring buffer */
		return (dst_cbuf[j] == 0) ? 1 : 0;
	} else if (seq_dist <= SEQ_MAX - KNET_CBUFFER_SIZE) {
		memset(dst_cbuf, 0, KNET_CBUFFER_SIZE);
		*dst_seq_num = seq_num;
	}

	/* cleaning up circular buffer */
	i = (*dst_seq_num + 1) % KNET_CBUFFER_SIZE;

	if (i > j) {
		memset(dst_cbuf + i, 0, KNET_CBUFFER_SIZE - i);
		memset(dst_cbuf, 0, j + 1);
	} else {
		memset(dst_cbuf + i, 0, j - i + 1);
	}

	*dst_seq_num = seq_num;

	return 1;
}

void _has_been_delivered(struct knet_host *host, int bcast, seq_num_t seq_num)
{

	if (bcast) {
		host->bcast_circular_buffer[seq_num % KNET_CBUFFER_SIZE] = 1;
	} else {
		host->ucast_circular_buffer[seq_num % KNET_CBUFFER_SIZE] = 1;
	}

	return;
}

int _dst_cache_update(knet_handle_t knet_h, uint16_t host_id)
{
	int write_retry = 0;
	int savederrno = 0;

try_again:
	if (write(knet_h->dstpipefd[1], &host_id, sizeof(host_id)) != sizeof(host_id)) {
		if ((write_retry < 10) && ((errno = EAGAIN) || (errno = EWOULDBLOCK))) {
			write_retry++;
			goto try_again;
		} else {
			savederrno = errno;
			log_debug(knet_h, KNET_SUB_COMMON, "Unable to write to dstpipefd[1]: %s",
				  strerror(savederrno));
			errno = savederrno;
			return -1;
		}
	}

	return 0;
}
