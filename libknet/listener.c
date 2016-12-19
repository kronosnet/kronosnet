/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <string.h>
#include <stdlib.h>

#include "internals.h"
#include "common.h"
#include "logging.h"
#include "listener.h"
#include "transports.h"

int _listener_add(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id)
{
	int count = 0;
	int savederrno = 0, err = 0;
	struct knet_link *lnk = &knet_h->host_index[host_id]->link[link_id];
	struct knet_listener *listener = NULL;

	savederrno = pthread_rwlock_wrlock(&knet_h->listener_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_LISTENER, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	listener = knet_h->listener_head;

	while (listener) {
		count++;
		log_debug(knet_h, KNET_SUB_LISTENER, "checking listener: %d", count);
		if (!memcmp(&lnk->src_addr, &listener->address, sizeof(struct sockaddr_storage))) {
			log_debug(knet_h, KNET_SUB_LISTENER, "found active listener");
			break;
		}
		listener = listener->next;
	}

	if (!listener) {
		listener = malloc(sizeof(struct knet_listener));
		if (!listener) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_LISTENER, "out of memory to allocate listener: %s",
				  strerror(savederrno));
			goto exit_unlock;
		}

		memset(listener, 0, sizeof(struct knet_listener));
		memmove(&listener->address, &lnk->src_addr, sizeof(struct sockaddr_storage));
		if (knet_h->transport_ops[lnk->transport_type]->link_listener_start(knet_h, lnk->transport, link_id,
										    &lnk->src_addr, &lnk->dst_addr) < 0) {
			savederrno = errno;
			err = -1;
			free(listener);
			listener = NULL;
			log_err(knet_h, KNET_SUB_LISTENER, "Unable to start listener for this link");
			goto exit_unlock;
		}

		/* pushing new host to the front */
		listener->next		= knet_h->listener_head;
		knet_h->listener_head	= listener;
	}
	lnk->listener_sock = listener->sock;

exit_unlock:
	if ((err) && (listener)) {
		if (listener->sock >= 0) {
			close(listener->sock);
		}
		free(listener);
		listener = NULL;
	}

	pthread_rwlock_unlock(&knet_h->listener_rwlock);
	errno = savederrno;
	return err;
}

int _listener_remove(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id)
{
	int err = 0, savederrno = 0;
	int link_idx;
	struct epoll_event ev; /* kernel < 2.6.9 bug (see epoll_ctl man) */
	struct knet_host *host;
	struct knet_link *lnk = &knet_h->host_index[host_id]->link[link_id];
	struct knet_listener *tmp_listener;
	struct knet_listener *listener;
	int listener_cnt = 0;

	savederrno = pthread_rwlock_wrlock(&knet_h->listener_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_LISTENER, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	/* checking if listener is in use */
	for (host = knet_h->host_head; host != NULL; host = host->next) {
		for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
			if (host->link[link_idx].status.enabled != 1)
				continue;

			if (host->link[link_idx].listener_sock == lnk->listener_sock) {
				listener_cnt++;
			}
		}
	}

	if (listener_cnt) {
		lnk->listener_sock = 0;
		log_debug(knet_h, KNET_SUB_LISTENER, "listener_remove: listener still in use");
		savederrno = EBUSY;
		err = -1;
		goto exit_unlock;
	}

	listener = knet_h->listener_head;
	while (listener) {
		if (listener->sock == lnk->listener_sock)
			break;
		listener = listener->next;
	}

	/* TODO: use a doubly-linked list? */
	if (listener == knet_h->listener_head) {
		knet_h->listener_head = knet_h->listener_head->next;
	} else {
		for (tmp_listener = knet_h->listener_head; tmp_listener != NULL; tmp_listener = tmp_listener->next) {
			if (listener == tmp_listener->next) {
				tmp_listener->next = tmp_listener->next->next;
				break;
			}
		}
	}

	knet_h->transport_ops[lnk->transport_type]->link_free(lnk->transport);
	lnk->transport = NULL;

	epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, listener->sock, &ev);
	close(listener->sock);
	free(listener);

 exit_unlock:
	pthread_rwlock_unlock(&knet_h->listener_rwlock);

	errno = savederrno;
	return err;
}
