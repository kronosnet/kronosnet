#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "libknet-private.h"

int knet_host_get(knet_handle_t knet_h, uint16_t node_id, struct knet_host **host)
{
	int ret;

	if ((ret = pthread_rwlock_rdlock(&knet_h->list_rwlock)) != 0)
		return ret;

	*host = knet_h->host_index[node_id];

	if (*host == NULL) {
		pthread_rwlock_unlock(&knet_h->list_rwlock);
		errno = ENOENT;
		return ENOENT;
	}

	return 0;
}

int knet_host_acquire(knet_handle_t knet_h, struct knet_host **host)
{
	int ret;

	if ((ret = pthread_rwlock_rdlock(&knet_h->list_rwlock)) != 0)
		return ret;

	*host = knet_h->host_head;

	return 0;
}

int knet_host_release(knet_handle_t knet_h, struct knet_host **host)
{
	int ret;

	*host = NULL;

	if ((ret = pthread_rwlock_unlock(&knet_h->list_rwlock)) != 0)
		return ret;

	return 0;
}

int knet_host_foreach(knet_handle_t knet_h, knet_link_fn_t linkfun, struct knet_host_search *data)
{
	int lockstatus;
	struct knet_host *host;

	lockstatus = pthread_rwlock_rdlock(&knet_h->list_rwlock);

	if ((lockstatus != 0) && (lockstatus != EDEADLK))
		return lockstatus;

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		if ((linkfun(knet_h, host, data)) != KNET_HOST_FOREACH_NEXT)
			break;
	}

	if (lockstatus == 0)
		pthread_rwlock_unlock(&knet_h->list_rwlock);

	return 0;
}

int knet_host_add(knet_handle_t knet_h, uint16_t node_id)
{
	int link_idx, ret = 0; /* success */
	struct knet_host *host, *tail;

	if ((ret = pthread_rwlock_wrlock(&knet_h->list_rwlock)) != 0)
		goto exit_clean;

	if (knet_h->host_index[node_id] != NULL) {
		errno = ret = EEXIST;
		goto exit_unlock;
	}

	if ((host = malloc(sizeof(struct knet_host))) == NULL)
		goto exit_unlock;

	memset(host, 0, sizeof(struct knet_host));

	host->node_id = node_id;

	for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++)
		host->link[link_idx].link_id = link_idx;

	/* adding new host to the index */
	knet_h->host_index[node_id] = host;

	if (!knet_h->host_head) {
		knet_h->host_head = host;
	} else {
		tail = knet_h->host_head;
		while (tail->next != NULL)
			tail = tail->next;

		tail->next = host;
	}

 exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);

 exit_clean:
	return ret;
}

int knet_host_remove(knet_handle_t knet_h, uint16_t node_id)
{
	int ret = 0; /* success */
	struct knet_host *host, *removed;

	if ((ret = pthread_rwlock_wrlock(&knet_h->list_rwlock)) != 0)
		goto exit_clean;

	if (knet_h->host_index[node_id] == NULL) {
		errno = ret = EINVAL;
		goto exit_unlock;
	}

	removed = NULL;

	/* removing host from list */
	if (knet_h->host_head->node_id == node_id) {
		removed = knet_h->host_head;
		knet_h->host_head = removed->next;
	} else {
		for (host = knet_h->host_head; host->next != NULL; host = host->next) {
			if (host->next->node_id == node_id) {
				removed = host->next;
				host->next = removed->next;
				break;
			}
		}
	}

	if (removed != NULL) {
		knet_h->host_index[node_id] = NULL;
		free(removed);
	}

 exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);

 exit_clean:
	return ret;
}

int knet_host_dst_cache_update(knet_handle_t knet_h, uint16_t node_id)
{
	int write_retry = 0;

try_again:
	if (write(knet_h->pipefd[1], &node_id, sizeof(node_id)) != sizeof(node_id)) {
		if ((write_retry < 10) && ((errno = EAGAIN) || (errno = EWOULDBLOCK))) {
			write_retry++;
			goto try_again;
		} else {
			return -1;
		}
	}
	return 0;
}

/* bcast = 0 -> unicast packet | 1 -> broadcast|mcast */

/* make this bcast/ucast aware */
int knet_should_deliver(struct knet_host *host, int bcast, seq_num_t seq_num)
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

void knet_has_been_delivered(struct knet_host *host, int bcast, seq_num_t seq_num)
{

	if (bcast) {
		host->bcast_circular_buffer[seq_num % KNET_CBUFFER_SIZE] = 1;
	} else {
		host->ucast_circular_buffer[seq_num % KNET_CBUFFER_SIZE] = 1;
	}

	return;
}
