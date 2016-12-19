/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
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
#include "transports.h"
#include "host.h"

int _link_updown(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
		 unsigned int enabled, unsigned int connected)
{
	struct knet_link *link = &knet_h->host_index[host_id]->link[link_id];

	if ((link->status.enabled == enabled) &&
	    (link->status.connected == connected))
		return 0;

	link->status.enabled = enabled;
	link->status.connected = connected;

	_host_dstcache_update_sync(knet_h, knet_h->host_index[host_id]);

	if ((link->status.dynconnected) &&
	    (!link->status.connected))
		link->status.dynconnected = 0;

	return 0;
}

int knet_link_set_config(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 uint8_t transport,
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

	if (transport >= KNET_MAX_TRANSPORTS) {
		errno = EINVAL;
		return -1;
	}

	if (!knet_h->transport_ops[transport]) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->global_rwlock);
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

	if (link->status.enabled != 0) {
		err =-1;
		savederrno = EBUSY;
		log_err(knet_h, KNET_SUB_LINK, "Host %u link %u is currently in use: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	memmove(&link->src_addr, src_addr, sizeof(struct sockaddr_storage));

	err = getnameinfo((const struct sockaddr *)src_addr, sizeof(struct sockaddr_storage),
			  link->status.src_ipaddr, KNET_MAX_HOST_LEN,
			  link->status.src_port, KNET_MAX_PORT_LEN,
			  NI_NUMERICHOST | NI_NUMERICSERV);
	if (err) {
		if (err == EAI_SYSTEM) {
			savederrno = errno;
			log_warn(knet_h, KNET_SUB_LINK,
				 "Unable to resolve host: %u link: %u source addr/port: %s",
				 host_id, link_id, strerror(savederrno));
		} else {
			savederrno = EINVAL;
			log_warn(knet_h, KNET_SUB_LINK,
				 "Unable to resolve host: %u link: %u source addr/port: %s",
				 host_id, link_id, gai_strerror(err));
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

	memmove(&link->dst_addr, dst_addr, sizeof(struct sockaddr_storage));
	err = getnameinfo((const struct sockaddr *)dst_addr, sizeof(struct sockaddr_storage),
			  link->status.dst_ipaddr, KNET_MAX_HOST_LEN,
			  link->status.dst_port, KNET_MAX_PORT_LEN,
			  NI_NUMERICHOST | NI_NUMERICSERV);
	if (err) {
		if (err == EAI_SYSTEM) {
			savederrno = errno;
			log_warn(knet_h, KNET_SUB_LINK,
				 "Unable to resolve host: %u link: %u destination addr/port: %s",
				 host_id, link_id, strerror(savederrno));
		} else {
			savederrno = EINVAL;
			log_warn(knet_h, KNET_SUB_LINK,
				 "Unable to resolve host: %u link: %u destination addr/port: %s",
				 host_id, link_id, gai_strerror(err));
		}
		err = -1;
	}

exit_unlock:
	if (!err) {
		link->transport_type = transport;
		link->configured = 1;
		link->pong_count = KNET_LINK_DEFAULT_PONG_COUNT;
		link->has_valid_mtu = 0;
		link->ping_interval = KNET_LINK_DEFAULT_PING_INTERVAL * 1000; /* microseconds */
		link->pong_timeout = KNET_LINK_DEFAULT_PING_TIMEOUT * 1000; /* microseconds */
		link->latency_fix = KNET_LINK_DEFAULT_PING_PRECISION;
		link->latency_exp = KNET_LINK_DEFAULT_PING_PRECISION - \
				    ((link->ping_interval * KNET_LINK_DEFAULT_PING_PRECISION) / 8000000);
	}
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_get_config(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 uint8_t *transport,
			 struct sockaddr_storage *src_addr,
			 struct sockaddr_storage *dst_addr,
			 uint8_t *dynamic)
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

	if (!dynamic) {
		errno = EINVAL;
		return -1;
	}

	if (!transport) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
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

	if (!link->configured) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is not configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	if ((link->dynamic == KNET_LINK_STATIC) && (!dst_addr)) {
		savederrno = EINVAL;
		err = -1;
		goto exit_unlock;
	}

	memmove(src_addr, &link->src_addr, sizeof(struct sockaddr_storage));

	*transport = link->transport_type;

	if (link->dynamic == KNET_LINK_STATIC) {
		*dynamic = 0;
		memmove(dst_addr, &link->dst_addr, sizeof(struct sockaddr_storage));
	} else {
		*dynamic = 1;
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_set_enable(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 unsigned int enabled)
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

	if (enabled > 1) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * this read lock might appear as an API violation, but be
	 * very careful because we cannot use a write lock (yet).
	 * the _send_host_info requires threads to be operational.
	 * a write lock here would deadlock.
	 * a read lock is sufficient as all functions invoked by
	 * this code are already thread safe.
	 */
	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
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

	if (!link->configured) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is not configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	if (link->status.enabled == enabled) {
		err = 0;
		goto exit_unlock;
	}

	if (enabled) {
		if (knet_h->transport_ops[link->transport_type]->link_allocate(
			    knet_h, knet_h->transports[link->transport_type],
			    link,
			    &link->transport, link_id,
			    &link->src_addr, &link->dst_addr,
			    &link->outsock) < 0) {
			savederrno = errno;
			err = -1;
			goto exit_unlock;
		}

		if (_listener_add(knet_h, host_id, link_id) < 0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_LINK, "Unable to setup listener for this link");
			goto exit_unlock;
		}
		log_debug(knet_h, KNET_SUB_LINK, "host: %u link: %u is enabled",
			  host_id, link_id);
	}

	if (!enabled) {
		struct knet_hostinfo knet_hostinfo;

		knet_hostinfo.khi_type = KNET_HOSTINFO_TYPE_LINK_UP_DOWN;
		knet_hostinfo.khi_bcast = KNET_HOSTINFO_UCAST;
		knet_hostinfo.khi_dst_node_id = host_id;
		knet_hostinfo.khip_link_status_link_id = link_id;
		knet_hostinfo.khip_link_status_status = KNET_HOSTINFO_LINK_STATUS_DOWN;
		_send_host_info(knet_h, &knet_hostinfo, KNET_HOSTINFO_LINK_STATUS_SIZE);
	}

	err = _link_updown(knet_h, host_id, link_id, enabled, link->status.connected);
	savederrno = errno;

	if ((!err) && (enabled)) {
		err = 0;
		goto exit_unlock;
	}

	if (err) {
		err = -1;
		goto exit_unlock;
	}

	err = _listener_remove(knet_h, host_id, link_id);
	savederrno = errno;

	if ((err) && (savederrno != EBUSY)) {
		log_err(knet_h, KNET_SUB_LINK, "Unable to remove listener for this link");
		if (_link_updown(knet_h, host_id, link_id, 1, link->status.connected)) {
			/* force link status the hard way */
			link->status.enabled = 1;
		}
		log_debug(knet_h, KNET_SUB_LINK, "host: %u link: %u is NOT disabled",
			  host_id, link_id);
		err = -1;
		goto exit_unlock;
	} else {
		err = 0;
		savederrno = 0;
	}

	log_debug(knet_h, KNET_SUB_LINK, "host: %u link: %u is disabled",
		  host_id, link_id);
	link->host_info_up_sent = 0;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_get_enable(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 unsigned int *enabled)
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

	if (!enabled) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
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

	if (!link->configured) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is not configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	*enabled = link->status.enabled;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_set_pong_count(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			     uint8_t pong_count)
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

	if (pong_count < 1) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->global_rwlock);
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

	if (!link->configured) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is not configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	link->pong_count = pong_count;

	log_debug(knet_h, KNET_SUB_LINK,
		  "host: %u link: %u pong count update: %u",
		  host_id, link_id, link->pong_count);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_get_pong_count(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			     uint8_t *pong_count)
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

	if (!pong_count) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
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

	if (!link->configured) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is not configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	*pong_count = link->pong_count;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_set_ping_timers(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			      time_t interval, time_t timeout, unsigned int precision)
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

	if (!interval) {
		errno = EINVAL;
		return -1;
	}

	if (!timeout) {
		errno = EINVAL;
		return -1;
	}

	if (!precision) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->global_rwlock);
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

	if (!link->configured) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is not configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	link->ping_interval = interval * 1000; /* microseconds */
	link->pong_timeout = timeout * 1000; /* microseconds */
	link->latency_fix = precision;
	link->latency_exp = precision - \
			    ((link->ping_interval * precision) / 8000000);

	log_debug(knet_h, KNET_SUB_LINK,
		  "host: %u link: %u timeout update - interval: %llu timeout: %llu precision: %d",
		  host_id, link_id, link->ping_interval, link->pong_timeout, precision);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_get_ping_timers(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			      time_t *interval, time_t *timeout, unsigned int *precision)
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

	if (!interval) {
		errno = EINVAL;
		return -1;
	}

	if (!timeout) {
		errno = EINVAL;
		return -1;
	}

	if (!precision) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
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

	if (!link->configured) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is not configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	*interval = link->ping_interval / 1000; /* microseconds */
	*timeout = link->pong_timeout / 1000;
	*precision = link->latency_fix;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_set_priority(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			   uint8_t priority)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;
	struct knet_link *link;
	uint8_t old_priority;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (link_id >= KNET_MAX_LINK) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&knet_h->global_rwlock);
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

	if (!link->configured) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is not configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	old_priority = link->priority;

	if (link->priority == priority) {
		err = 0;
		goto exit_unlock;
	}

	link->priority = priority;

	if (_host_dstcache_update_async(knet_h, host)) {
		savederrno = errno;
		log_debug(knet_h, KNET_SUB_LINK,
			  "Unable to update link priority (host: %u link: %u priority: %u): %s",
			  host_id, link_id, link->priority, strerror(savederrno));
		link->priority = old_priority;
		err = -1;
		goto exit_unlock;
	}

	log_debug(knet_h, KNET_SUB_LINK,
		  "host: %u link: %u priority set to: %u",
		  host_id, link_id, link->priority);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_get_priority(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			   uint8_t *priority)
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

	if (!priority) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
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

	if (!link->configured) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is not configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	*priority = link->priority;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_get_link_list(knet_handle_t knet_h, uint16_t host_id,
			    uint8_t *link_ids, size_t *link_ids_entries)
{
	int savederrno = 0, err = 0, i, count = 0;
	struct knet_host *host;
	struct knet_link *link;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!link_ids) {
		errno = EINVAL;
		return -1;
	}

	if (!link_ids_entries) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
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

	for (i = 0; i < KNET_MAX_LINK; i++) {
		link = &host->link[i];
		if (!link->configured) {
			continue;
		}
		link_ids[count] = i;
		count++;
	}

	*link_ids_entries = count;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}

int knet_link_get_status(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id,
			 struct knet_link_status *status)
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

	if (!status) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
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

	if (!link->configured) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is not configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	memmove(status, &link->status, sizeof(struct knet_link_status));

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = savederrno;
	return err;
}
