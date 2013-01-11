/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "internals.h"
#include "logging.h"
#include "link.h"
#include "listener.h"
#include "onwire.h"
#include "host.h"

int _link_updown(knet_handle_t knet_h, uint16_t node_id,
			    struct knet_link *lnk, int configured, int connected)
{
	unsigned int old_configured = lnk->status.configured;
	unsigned int old_connected = lnk->status.connected;

	if ((lnk->status.configured == configured) && (lnk->status.connected == connected))
		return 0;

	lnk->status.configured = configured;
	lnk->status.connected = connected;

	if (_dst_cache_update(knet_h, node_id)) {
		log_debug(knet_h, KNET_SUB_LINK,
			  "Unable to update link status (host: %s link: %s configured: %u connected: %u)",
			  knet_h->host_index[node_id]->name,
			  lnk->status.dst_ipaddr,
			  lnk->status.configured,
			  lnk->status.connected);
		lnk->status.configured = old_configured;
		lnk->status.connected = old_connected;
		return -1;
	}

	if ((lnk->status.dynconnected) && (!lnk->status.connected))
		lnk->status.dynconnected = 0;

	return 0;
}

int knet_link_enable(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, int configured)
{
	int err;
	struct knet_link *lnk;

	if (!knet_h->host_index[node_id])
		return -1;

	lnk = &knet_h->host_index[node_id]->link[link_id];

	if (lnk->status.configured == configured)
		return 0;

	if (configured) {
		if (_listener_add(knet_h, lnk) < 0) {
			log_err(knet_h, KNET_SUB_LINK, "Unable to setup listener for this link");
			return -1;
		}
		log_debug(knet_h, KNET_SUB_LINK, "host: %s link: %s is enabled",
			  knet_h->host_index[node_id]->name, lnk->status.dst_ipaddr);
	}

	if (!configured) {
		struct knet_hinfo_data knet_hinfo_data;

		knet_hinfo_data.khd_type = KNET_HOST_INFO_LINK_UP_DOWN;
		knet_hinfo_data.khd_bcast = 0;
		knet_hinfo_data.khd_dst_node_id = htons(node_id);
		knet_hinfo_data.khd_dype.link_up_down.khdt_link_id = lnk->link_id;
		knet_hinfo_data.khd_dype.link_up_down.khdt_link_status = 0;

		_send_host_info(knet_h, &knet_hinfo_data, sizeof(struct knet_hinfo_data));
	}

	err = _link_updown(knet_h, node_id, lnk, configured, lnk->status.connected);

	if ((configured) && (!err))
		return 0;

	if (err)
		return -1;

	err = _listener_remove(knet_h, lnk);

	if ((err) && (err != EBUSY)) {
		log_err(knet_h, KNET_SUB_LINK, "Unable to remove listener for this link");
		if (_link_updown(knet_h, node_id, lnk, 1, lnk->status.connected))
			lnk->status.configured = 1;
		log_debug(knet_h, KNET_SUB_LINK, "host: %s link: %s is NOT disabled",
			  knet_h->host_index[node_id]->name, lnk->status.dst_ipaddr);
		return -1;
	}
	log_debug(knet_h, KNET_SUB_LINK, "host: %s link: %s is disabled",
		  knet_h->host_index[node_id]->name, lnk->status.dst_ipaddr);
	lnk->host_info_up_sent = 0;
	return 0;
}

int knet_link_get_priority(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, uint8_t *priority)
{
	if (!knet_h->host_index[node_id])
		return -1;

	*priority = knet_h->host_index[node_id]->link[link_id].priority;

	return 0;
}

int knet_link_set_priority(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id, uint8_t priority)
{
	struct knet_link *lnk;
	uint8_t old_priority;

	if (!knet_h->host_index[node_id])
		return -1;

	lnk = &knet_h->host_index[node_id]->link[link_id];
	old_priority = lnk->priority;

	if (lnk->priority == priority)
		return 0;

	lnk->priority = priority;

	if (_dst_cache_update(knet_h, node_id)) {
		log_debug(knet_h, KNET_SUB_LINK,
			  "Unable to update link priority (host: %s link: %s priority: %u)",
			  knet_h->host_index[node_id]->name,
			  lnk->status.dst_ipaddr,
			  lnk->priority);
		lnk->priority = old_priority;
		return -1;
	}

	log_debug(knet_h, KNET_SUB_LINK,
		  "host: %s link: %s priority set to: %u",
		  knet_h->host_index[node_id]->name,
		  lnk->status.dst_ipaddr,
		  lnk->priority);

	return 0;
}

int knet_link_set_timeout(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id,
				time_t interval, time_t timeout, unsigned int precision)
{
	struct knet_link *lnk;

	if (!knet_h->host_index[node_id])
		return -1;

	lnk = &knet_h->host_index[node_id]->link[link_id];

	lnk->ping_interval = interval * 1000; /* microseconds */
	lnk->pong_timeout = timeout * 1000; /* microseconds */
	lnk->latency_fix = precision;
	lnk->latency_exp = precision - \
				((lnk->ping_interval * precision) / 8000000);
	log_debug(knet_h, KNET_SUB_LINK,
		  "host: %s link: %s timeout update - interval: %llu timeout: %llu precision: %d",
		  knet_h->host_index[node_id]->name, lnk->status.dst_ipaddr,
		  lnk->ping_interval, lnk->pong_timeout, precision);

	return 0;
}

int knet_link_get_timeout(knet_handle_t knet_h, uint16_t node_id, uint8_t link_id,
				time_t *interval, time_t *timeout, unsigned int *precision)
{
	struct knet_link *lnk;

	if (!knet_h->host_index[node_id])
		return -1;

	lnk = &knet_h->host_index[node_id]->link[link_id];

	*interval = lnk->ping_interval / 1000; /* microseconds */
	*timeout = lnk->pong_timeout / 1000;
	*precision = lnk->latency_fix;

	return 0;
}

int knet_link_set_config(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 struct sockaddr_storage *src_addr,
			 struct sockaddr_storage *dst_addr)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;
	struct knet_link *link;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (link_id >= KNET_MAX_LINK) {
		errno = EINVAL;
		return -1;
	}

	if (!src_addr) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_LINK, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	host = knet_h->host_index[host_id];
	if (!host) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "Unable to find host %u: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	link = &host->link[link_id];

	/* rememeber to check if link is on traffic before allowing reconfig */

	memcpy(&link->src_addr, src_addr, sizeof(struct sockaddr_storage));

	err = getnameinfo((const struct sockaddr *)src_addr, sizeof(struct sockaddr_storage),
			  link->status.src_ipaddr, KNET_MAX_HOST_LEN,
			  link->status.src_port, KNET_MAX_PORT_LEN,
			  NI_NUMERICHOST | NI_NUMERICSERV);
	if (err) {
		if (err == EAI_SYSTEM) {
			savederrno = errno;
			log_warn(knet_h, KNET_SUB_LINK,
				 "Unable to resolve host: %s link: %u source addr/port: %s",
				 host->name, link_id, strerror(savederrno));
		} else {
			savederrno = EINVAL;
			log_warn(knet_h, KNET_SUB_LINK,
				 "Unable to resolve host: %s link: %u source addr/port: %s",
				 host->name, link_id, gai_strerror(err));
		}
		err = -1;
		goto exit_unlock;
	}

	if (!dst_addr) {
		link->dynamic = KNET_LINK_DYNIP;
		err = 0;
		goto exit_unlock;
	}

	link->dynamic = KNET_LINK_STATIC;

	memcpy(&link->dst_addr, dst_addr, sizeof(struct sockaddr_storage));
	err = getnameinfo((const struct sockaddr *)dst_addr, sizeof(struct sockaddr_storage),
			  link->status.dst_ipaddr, KNET_MAX_HOST_LEN,
			  link->status.dst_port, KNET_MAX_PORT_LEN,
			  NI_NUMERICHOST | NI_NUMERICSERV);
	if (err) {
		if (err == EAI_SYSTEM) {
			savederrno = errno;
			log_warn(knet_h, KNET_SUB_LINK,
				 "Unable to resolve host: %s link: %u destination addr/port: %s",
				 host->name, link_id, strerror(savederrno));
		} else {
			savederrno = EINVAL;
			log_warn(knet_h, KNET_SUB_LINK,
				 "Unable to resolve host: %s link: %u destination addr/port: %s",
				 host->name, link_id, gai_strerror(err));
		}
		err = -1;
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_get_config(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 struct sockaddr_storage *src_addr,
			 struct sockaddr_storage *dst_addr)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;
	struct knet_link *link;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (link_id >= KNET_MAX_LINK) {
		errno = EINVAL;
		return -1;
	}

	if (!src_addr) {
		errno = EINVAL;
		return -1;
	}

	if (!dst_addr) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->list_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_LINK, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	host = knet_h->host_index[host_id];
	if (!host) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "Unable to find host %u: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	link = &host->link[link_id];

	memcpy(src_addr, &link->src_addr, sizeof(struct sockaddr_storage));

	if (link->dynamic == KNET_LINK_DYNIP) {
		err = 1;
		goto exit_unlock;
	}

	memcpy(dst_addr, &link->dst_addr, sizeof(struct sockaddr_storage));

exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_get_status(knet_handle_t knet_h,
			 uint16_t node_id,
			 uint8_t link_id,
			 struct knet_link_status *status)
{
	if (!knet_h->host_index[node_id])
		return -1;

	memcpy(status, &knet_h->host_index[node_id]->link[link_id].status, sizeof(struct knet_link_status));

	return 0;
}
