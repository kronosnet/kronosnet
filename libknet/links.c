/*
 * Copyright (C) 2012-2019 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>

#include "internals.h"
#include "logging.h"
#include "links.h"
#include "transports.h"
#include "host.h"
#include "threads_common.h"
#include "links_acl.h"

int _link_updown(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
		 unsigned int enabled, unsigned int connected)
{
	struct knet_link *link = &knet_h->host_index[host_id]->link[link_id];

	if ((link->status.enabled == enabled) &&
	    (link->status.connected == connected))
		return 0;

	link->status.enabled = enabled;
	link->status.connected = connected;

	_host_dstcache_update_async(knet_h, knet_h->host_index[host_id]);

	if ((link->status.dynconnected) &&
	    (!link->status.connected))
		link->status.dynconnected = 0;

	if (connected) {
		time(&link->status.stats.last_up_times[link->status.stats.last_up_time_index]);
		link->status.stats.up_count++;
		if (++link->status.stats.last_up_time_index >= MAX_LINK_EVENTS) {
			link->status.stats.last_up_time_index = 0;
		}
	} else {
		time(&link->status.stats.last_down_times[link->status.stats.last_down_time_index]);
		link->status.stats.down_count++;
		if (++link->status.stats.last_down_time_index >= MAX_LINK_EVENTS) {
			link->status.stats.last_down_time_index = 0;
		}
	}
	return 0;
}

void _link_clear_stats(knet_handle_t knet_h)
{
	struct knet_host *host;
	struct knet_link *link;
	uint32_t host_id;
	uint8_t link_id;

	for (host_id = 0; host_id < KNET_MAX_HOST; host_id++) {
		host = knet_h->host_index[host_id];
		if (!host) {
			continue;
		}
		for (link_id = 0; link_id < KNET_MAX_LINK; link_id++) {
			link = &host->link[link_id];
			memset(&link->status.stats, 0, sizeof(struct knet_link_stats));
		}
	}
}

int knet_link_set_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			 uint8_t transport,
			 struct sockaddr_storage *src_addr,
			 struct sockaddr_storage *dst_addr,
			 uint64_t flags)
{
	int savederrno = 0, err = 0, i;
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

	if (dst_addr && (src_addr->ss_family != dst_addr->ss_family)) {
		log_err(knet_h, KNET_SUB_LINK, "Source address family does not match destination address family");
		errno = EINVAL;
		return -1;
	}

	if (transport >= KNET_MAX_TRANSPORTS) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_LINK, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (transport == KNET_TRANSPORT_LOOPBACK && knet_h->host_id != host_id) {
		log_err(knet_h, KNET_SUB_LINK, "Cannot create loopback link to remote node");
		err = -1;
		savederrno = EINVAL;
		goto exit_unlock;
	}

	if (knet_h->host_id == host_id && knet_h->has_loop_link) {
		log_err(knet_h, KNET_SUB_LINK, "Cannot create more than 1 link when loopback is active");
		err = -1;
		savederrno = EINVAL;
		goto exit_unlock;
	}

	host = knet_h->host_index[host_id];
	if (!host) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "Unable to find host %u: %s",
			host_id, strerror(savederrno));
		goto exit_unlock;
	}

	if (transport == KNET_TRANSPORT_LOOPBACK && knet_h->host_id == host_id) {
		for (i=0; i<KNET_MAX_LINK; i++) {
			if (host->link[i].configured) {
				log_err(knet_h, KNET_SUB_LINK, "Cannot add loopback link when other links are already configured.");
				err = -1;
				savederrno = EINVAL;
				goto exit_unlock;
			}
		}
	}

	link = &host->link[link_id];

	if (link->configured != 0) {
		err =-1;
		savederrno = EBUSY;
		log_err(knet_h, KNET_SUB_LINK, "Host %u link %u is currently configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	if (link->status.enabled != 0) {
		err =-1;
		savederrno = EBUSY;
		log_err(knet_h, KNET_SUB_LINK, "Host %u link %u is currently in use: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	memmove(&link->src_addr, src_addr, sizeof(struct sockaddr_storage));

	err = knet_addrtostr(src_addr, sizeof(struct sockaddr_storage),
			     link->status.src_ipaddr, KNET_MAX_HOST_LEN,
			     link->status.src_port, KNET_MAX_PORT_LEN);
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
	} else {

		link->dynamic = KNET_LINK_STATIC;

		memmove(&link->dst_addr, dst_addr, sizeof(struct sockaddr_storage));
		err = knet_addrtostr(dst_addr, sizeof(struct sockaddr_storage),
				     link->status.dst_ipaddr, KNET_MAX_HOST_LEN,
				     link->status.dst_port, KNET_MAX_PORT_LEN);
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
			goto exit_unlock;
		}
	}

	link->pmtud_crypto_timeout_multiplier = KNET_LINK_PMTUD_CRYPTO_TIMEOUT_MULTIPLIER_MIN;
	link->pong_count = KNET_LINK_DEFAULT_PONG_COUNT;
	link->has_valid_mtu = 0;
	link->ping_interval = KNET_LINK_DEFAULT_PING_INTERVAL * 1000; /* microseconds */
	link->pong_timeout = KNET_LINK_DEFAULT_PING_TIMEOUT * 1000; /* microseconds */
	link->pong_timeout_backoff = KNET_LINK_PONG_TIMEOUT_BACKOFF;
	link->pong_timeout_adj = link->pong_timeout * link->pong_timeout_backoff; /* microseconds */
	link->latency_fix = KNET_LINK_DEFAULT_PING_PRECISION;
	link->latency_exp = KNET_LINK_DEFAULT_PING_PRECISION - \
			    ((link->ping_interval * KNET_LINK_DEFAULT_PING_PRECISION) / 8000000);
	link->flags = flags;

	if (transport_link_set_config(knet_h, link, transport) < 0) {
		savederrno = errno;
		err = -1;
		goto exit_unlock;
	}

	/*
	 * we can only configure default access lists if we know both endpoints
	 * and the protocol uses GENERIC_ACL, otherwise the protocol has
	 * to setup their own access lists above in transport_link_set_config.
	 */
	if ((transport_get_acl_type(knet_h, transport) == USE_GENERIC_ACL) &&
	    (link->dynamic == KNET_LINK_STATIC)) {
		log_debug(knet_h, KNET_SUB_LINK, "Configuring default access lists for host: %u link: %u socket: %d",
			  host_id, link_id, link->outsock);
		if ((check_add(knet_h, link->outsock, transport, -1,
			       &link->dst_addr, &link->dst_addr,
			       CHECK_TYPE_ADDRESS, CHECK_ACCEPT) < 0) && (errno != EEXIST)) {
			log_warn(knet_h, KNET_SUB_LINK, "Failed to configure default access lists for host: %u link: %u", host_id, link_id);
			savederrno = errno;
			err = -1;
			goto exit_unlock;
		}
	}

	link->configured = 1;
	log_debug(knet_h, KNET_SUB_LINK, "host: %u link: %u is configured",
		  host_id, link_id);

	if (transport == KNET_TRANSPORT_LOOPBACK) {
		knet_h->has_loop_link = 1;
		knet_h->loop_link = link_id;
		host->status.reachable = 1;
		link->status.mtu = KNET_PMTUD_SIZE_V6;
	} else {
		/*
		 * calculate the minimum MTU that is safe to use,
		 * based on RFCs and that each network device should
		 * be able to support without any troubles
		 */
		if (link->dynamic == KNET_LINK_STATIC) {
			/*
			 * with static link we can be more precise than using
			 * the generic calc_min_mtu()
			 */
			switch (link->dst_addr.ss_family) {
				case AF_INET6:
					link->status.mtu =  calc_max_data_outlen(knet_h, KNET_PMTUD_MIN_MTU_V6 - (KNET_PMTUD_OVERHEAD_V6 + link->proto_overhead));
					break;
				case AF_INET:
					link->status.mtu =  calc_max_data_outlen(knet_h, KNET_PMTUD_MIN_MTU_V4 - (KNET_PMTUD_OVERHEAD_V4 + link->proto_overhead));
					break;
			}
		} else {
			/*
			 * for dynamic links we start with the minimum MTU
			 * possible and PMTUd will kick in immediately
			 * after connection status is 1
			 */
			link->status.mtu =  calc_min_mtu(knet_h);
		}
		link->has_valid_mtu = 1;
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_get_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			 uint8_t *transport,
			 struct sockaddr_storage *src_addr,
			 struct sockaddr_storage *dst_addr,
			 uint8_t *dynamic,
			 uint64_t *flags)
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

	if (!flags) {
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

	*transport = link->transport;
	*flags = link->flags;

	if (link->dynamic == KNET_LINK_STATIC) {
		*dynamic = 0;
		memmove(dst_addr, &link->dst_addr, sizeof(struct sockaddr_storage));
	} else {
		*dynamic = 1;
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_clear_config(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;
	struct knet_link *link;
	int sock;
	uint8_t transport;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (link_id >= KNET_MAX_LINK) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
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

	if (link->configured != 1) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "Host %u link %u is not configured: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	if (link->status.enabled != 0) {
		err = -1;
		savederrno = EBUSY;
		log_err(knet_h, KNET_SUB_LINK, "Host %u link %u is currently in use: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	/*
	 * remove well known access lists here.
	 * After the transport has done clearing the config,
	 * then we can remove any leftover access lists if the link
	 * is no longer in use.
	 */
	if ((transport_get_acl_type(knet_h, link->transport) == USE_GENERIC_ACL) &&
	    (link->dynamic == KNET_LINK_STATIC)) {
		if ((check_rm(knet_h, link->outsock, link->transport,
			      &link->dst_addr, &link->dst_addr,
			      CHECK_TYPE_ADDRESS, CHECK_ACCEPT) < 0) && (errno != ENOENT)) {
			err = -1;
			savederrno = errno;
			log_err(knet_h, KNET_SUB_LINK, "Host %u link %u: unable to remove default access list",
				host_id, link_id);
			goto exit_unlock;
		}
	}

	/*
	 * cache it for later as we don't know if the transport
	 * will clear link info during clear_config.
	 */
	sock = link->outsock;
	transport = link->transport;

	if ((transport_link_clear_config(knet_h, link) < 0)  &&
	    (errno != EBUSY)) {
		savederrno = errno;
		err = -1;
		goto exit_unlock;
	}

	/*
	 * remove any other access lists when the socket is no
	 * longer in use by the transport.
	 */
	if ((transport_get_acl_type(knet_h, link->transport) == USE_GENERIC_ACL) &&
	    (knet_h->knet_transport_fd_tracker[sock].transport == KNET_MAX_TRANSPORTS)) {
		check_rmall(knet_h, sock, transport);
	}

	memset(link, 0, sizeof(struct knet_link));
	link->link_id = link_id;

	if (knet_h->has_loop_link && host_id == knet_h->host_id && link_id == knet_h->loop_link) {
		knet_h->has_loop_link = 0;
		if (host->active_link_entries == 0) {
			host->status.reachable = 0;
		}
	}

	log_debug(knet_h, KNET_SUB_LINK, "host: %u link: %u config has been wiped",
		  host_id, link_id);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_set_enable(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
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

	savederrno = get_global_wrlock(knet_h);
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

	err = _link_updown(knet_h, host_id, link_id, enabled, link->status.connected);
	savederrno = errno;

	if (enabled) {
		goto exit_unlock;
	}

	log_debug(knet_h, KNET_SUB_LINK, "host: %u link: %u is disabled",
		  host_id, link_id);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_get_enable(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
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
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_set_pong_count(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
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

	savederrno = get_global_wrlock(knet_h);
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
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_get_pong_count(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
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
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_set_ping_timers(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
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
		errno = ENOSYS;
		return -1;
	}

	if (!precision) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
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
		  "host: %u link: %u timeout update - interval: %llu timeout: %llu precision: %u",
		  host_id, link_id, link->ping_interval, link->pong_timeout, precision);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_get_ping_timers(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
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
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_set_priority(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
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

	savederrno = get_global_wrlock(knet_h);
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

	if (_host_dstcache_update_sync(knet_h, host)) {
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
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_get_priority(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
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
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_get_link_list(knet_handle_t knet_h, knet_node_id_t host_id,
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
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_get_status(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			 struct knet_link_status *status, size_t struct_size)
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

	savederrno = get_global_wrlock(knet_h);
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

	memmove(status, &link->status, struct_size);

	/* Calculate totals - no point in doing this on-the-fly */
	status->stats.rx_total_packets =
		status->stats.rx_data_packets +
		status->stats.rx_ping_packets +
		status->stats.rx_pong_packets +
		status->stats.rx_pmtu_packets;
	status->stats.tx_total_packets =
		status->stats.tx_data_packets +
		status->stats.tx_ping_packets +
		status->stats.tx_pong_packets +
		status->stats.tx_pmtu_packets;
	status->stats.rx_total_bytes =
		status->stats.rx_data_bytes +
		status->stats.rx_ping_bytes +
		status->stats.rx_pong_bytes +
		status->stats.rx_pmtu_bytes;
	status->stats.tx_total_bytes =
		status->stats.tx_data_bytes +
		status->stats.tx_ping_bytes +
		status->stats.tx_pong_bytes +
		status->stats.tx_pmtu_bytes;
	status->stats.tx_total_errors =
		status->stats.tx_data_errors +
		status->stats.tx_ping_errors +
		status->stats.tx_pong_errors +
		status->stats.tx_pmtu_errors;
	status->stats.tx_total_retries =
		status->stats.tx_data_retries +
		status->stats.tx_ping_retries +
		status->stats.tx_pong_retries +
		status->stats.tx_pmtu_retries;

	/* Tell the caller our full size in case they have an old version */
	status->size = sizeof(struct knet_link_status);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_link_add_acl(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
		      struct sockaddr_storage *ss1,
		      struct sockaddr_storage *ss2,
		      check_type_t type, check_acceptreject_t acceptreject)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;
	struct knet_link *link;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!ss1) {
		errno = EINVAL;
		return -1;
	}

	if ((type != CHECK_TYPE_ADDRESS) &&
	    (type != CHECK_TYPE_MASK) &&
	    (type != CHECK_TYPE_RANGE)) {
		errno = EINVAL;
		return -1;
	}

	if ((acceptreject != CHECK_ACCEPT) &&
	    (acceptreject != CHECK_REJECT)) {
		errno = EINVAL;
		return -1;
	}

	if ((type != CHECK_TYPE_ADDRESS) && (!ss2)) {
		errno = EINVAL;
		return -1;
	}

	if ((type == CHECK_TYPE_RANGE) &&
	    (ss1->ss_family != ss2->ss_family)) {
			errno = EINVAL;
			return -1;
	}

	if (link_id >= KNET_MAX_LINK) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
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

	if (link->dynamic != KNET_LINK_DYNIP) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is a point to point connection: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	err = check_add(knet_h, transport_link_get_acl_fd(knet_h, link), link->transport, -1,
			ss1, ss2, type, acceptreject);
	savederrno = errno;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);

	errno = savederrno;
	return err;
}

int knet_link_insert_acl(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
			 int index,
			 struct sockaddr_storage *ss1,
			 struct sockaddr_storage *ss2,
			 check_type_t type, check_acceptreject_t acceptreject)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;
	struct knet_link *link;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!ss1) {
		errno = EINVAL;
		return -1;
	}

	if ((type != CHECK_TYPE_ADDRESS) &&
	    (type != CHECK_TYPE_MASK) &&
	    (type != CHECK_TYPE_RANGE)) {
		errno = EINVAL;
		return -1;
	}

	if ((acceptreject != CHECK_ACCEPT) &&
	    (acceptreject != CHECK_REJECT)) {
		errno = EINVAL;
		return -1;
	}

	if ((type != CHECK_TYPE_ADDRESS) && (!ss2)) {
		errno = EINVAL;
		return -1;
	}

	if ((type == CHECK_TYPE_RANGE) &&
	    (ss1->ss_family != ss2->ss_family)) {
			errno = EINVAL;
			return -1;
	}

	if (link_id >= KNET_MAX_LINK) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
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

	if (link->dynamic != KNET_LINK_DYNIP) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is a point to point connection: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	err = check_add(knet_h, transport_link_get_acl_fd(knet_h, link), link->transport, index,
			ss1, ss2, type, acceptreject);
	savederrno = errno;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);

	errno = savederrno;
	return err;
}

int knet_link_rm_acl(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id,
		     struct sockaddr_storage *ss1,
		     struct sockaddr_storage *ss2,
		     check_type_t type, check_acceptreject_t acceptreject)
{
	int savederrno = 0, err = 0;
	struct knet_host *host;
	struct knet_link *link;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!ss1) {
		errno = EINVAL;
		return -1;
	}

	if ((type != CHECK_TYPE_ADDRESS) &&
	    (type != CHECK_TYPE_MASK) &&
	    (type != CHECK_TYPE_RANGE)) {
		errno = EINVAL;
		return -1;
	}

	if ((acceptreject != CHECK_ACCEPT) &&
	    (acceptreject != CHECK_REJECT)) {
		errno = EINVAL;
		return -1;
	}

	if ((type != CHECK_TYPE_ADDRESS) && (!ss2)) {
		errno = EINVAL;
		return -1;
	}

	if ((type == CHECK_TYPE_RANGE) &&
	    (ss1->ss_family != ss2->ss_family)) {
			errno = EINVAL;
			return -1;
	}

	if (link_id >= KNET_MAX_LINK) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
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

	if (link->dynamic != KNET_LINK_DYNIP) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is a point to point connection: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	err = check_rm(knet_h, transport_link_get_acl_fd(knet_h, link), link->transport,
		       ss1, ss2, type, acceptreject);
	savederrno = errno;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);

	errno = savederrno;
	return err;
}

int knet_link_clear_acl(knet_handle_t knet_h, knet_node_id_t host_id, uint8_t link_id)
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

	savederrno = get_global_wrlock(knet_h);
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

	if (link->dynamic != KNET_LINK_DYNIP) {
		err = -1;
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_LINK, "host %u link %u is a point to point connection: %s",
			host_id, link_id, strerror(savederrno));
		goto exit_unlock;
	}

	check_rmall(knet_h, transport_link_get_acl_fd(knet_h, link), link->transport);

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);

	errno = savederrno;
	return err;
}
