/*
 * Copyright (C) 2017-2023 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "libknet.h"
#include "compat.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "common.h"
#include "transports.h"
#include "transport_loopback.h"
#include "transport_udp.h"
#include "transport_sctp.h"
#include "threads_common.h"

#define empty_module 0, -1, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },

static knet_transport_ops_t transport_modules_cmd[KNET_MAX_TRANSPORTS] = {
	{ "LOOPBACK", KNET_TRANSPORT_LOOPBACK, 1, TRANSPORT_PROTO_LOOPBACK, USE_NO_ACL, TRANSPORT_PROTO_NOT_CONNECTION_ORIENTED, KNET_PMTUD_LOOPBACK_OVERHEAD, loopback_transport_init, loopback_transport_free, loopback_transport_link_set_config, loopback_transport_link_clear_config, loopback_transport_link_dyn_connect, loopback_transport_rx_sock_error, loopback_transport_tx_sock_error, loopback_transport_rx_is_data, loopback_transport_link_is_down },
	{ "UDP", KNET_TRANSPORT_UDP, 1, TRANSPORT_PROTO_IP_PROTO, USE_GENERIC_ACL, TRANSPORT_PROTO_NOT_CONNECTION_ORIENTED, KNET_PMTUD_UDP_OVERHEAD, udp_transport_init, udp_transport_free, udp_transport_link_set_config, udp_transport_link_clear_config, udp_transport_link_dyn_connect, udp_transport_rx_sock_error, udp_transport_tx_sock_error, udp_transport_rx_is_data, udp_transport_link_is_down },
	{ "SCTP", KNET_TRANSPORT_SCTP,
#ifdef HAVE_NETINET_SCTP_H
				       1, TRANSPORT_PROTO_IP_PROTO, USE_PROTO_ACL, TRANSPORT_PROTO_IS_CONNECTION_ORIENTED, KNET_PMTUD_SCTP_OVERHEAD, sctp_transport_init, sctp_transport_free, sctp_transport_link_set_config, sctp_transport_link_clear_config, sctp_transport_link_dyn_connect, sctp_transport_rx_sock_error, sctp_transport_tx_sock_error, sctp_transport_rx_is_data, sctp_transport_link_is_down },
#else
empty_module
#endif
	{ NULL, KNET_MAX_TRANSPORTS, empty_module
};

/*
 * transport wrappers
 */

int start_all_transports(knet_handle_t knet_h)
{
	int idx = 0, savederrno = 0, err = 0;

	while (transport_modules_cmd[idx].transport_name != NULL) {
		if (transport_modules_cmd[idx].built_in) {
			if (transport_modules_cmd[idx].transport_init(knet_h) < 0) {
				savederrno = errno;
				log_err(knet_h, KNET_SUB_HANDLE,
					"Failed to allocate transport handle for %s: %s",
					transport_modules_cmd[idx].transport_name,
					strerror(savederrno));
				err = -1;
				goto out;
			}
		}
		idx++;
	}

out:
	errno = savederrno;
	return err;
}

void stop_all_transports(knet_handle_t knet_h)
{
	int idx = 0;

	while (transport_modules_cmd[idx].transport_name != NULL) {
		if (transport_modules_cmd[idx].built_in) {
			transport_modules_cmd[idx].transport_free(knet_h);
		}
		idx++;
	}
}

int transport_link_set_config(knet_handle_t knet_h, struct knet_link *kn_link, uint8_t transport)
{
	if (!transport_modules_cmd[transport].built_in) {
		errno = EINVAL;
		return -1;
	}
	kn_link->transport_connected = 0;
	kn_link->transport = transport;
	kn_link->proto_overhead = transport_modules_cmd[transport].transport_mtu_overhead;
	return transport_modules_cmd[transport].transport_link_set_config(knet_h, kn_link);
}

int transport_link_clear_config(knet_handle_t knet_h, struct knet_link *kn_link)
{
	return transport_modules_cmd[kn_link->transport].transport_link_clear_config(knet_h, kn_link);
}

int transport_link_dyn_connect(knet_handle_t knet_h, int sockfd, struct knet_link *kn_link)
{
	return transport_modules_cmd[kn_link->transport].transport_link_dyn_connect(knet_h, sockfd, kn_link);
}

int transport_rx_sock_error(knet_handle_t knet_h, uint8_t transport, int sockfd, int recv_err, int recv_errno)
{
	return transport_modules_cmd[transport].transport_rx_sock_error(knet_h, sockfd, recv_err, recv_errno);
}

	int transport_tx_sock_error(knet_handle_t knet_h, uint8_t transport, int sockfd, int subsys, int recv_err, int recv_errno)
{
	return transport_modules_cmd[transport].transport_tx_sock_error(knet_h, sockfd, subsys, recv_err, recv_errno);
}

int transport_rx_is_data(knet_handle_t knet_h, uint8_t transport, int sockfd, struct knet_mmsghdr *msg)
{
	return transport_modules_cmd[transport].transport_rx_is_data(knet_h, sockfd, msg);
}

int transport_get_proto(knet_handle_t knet_h, uint8_t transport)
{
	return transport_modules_cmd[transport].transport_protocol;
}

int transport_get_acl_type(knet_handle_t knet_h, uint8_t transport)
{
	return transport_modules_cmd[transport].transport_acl_type;
}

int transport_get_connection_oriented(knet_handle_t knet_h, uint8_t transport)
{
	return transport_modules_cmd[transport].transport_is_connection_oriented;
}

int transport_link_is_down(knet_handle_t knet_h, struct knet_link *kn_link)
{
	return transport_modules_cmd[kn_link->transport].transport_link_is_down(knet_h, kn_link);
}

/*
 * public api
 */

int knet_get_transport_list(struct knet_transport_info *transport_list,
			    size_t *transport_list_entries)
{
	int err = 0;
	int idx = 0;
	int outidx = 0;

	if (!transport_list_entries) {
		errno = EINVAL;
		return -1;
	}

	while (transport_modules_cmd[idx].transport_name != NULL) {
		if (transport_modules_cmd[idx].built_in) {
			if (transport_list) {
				transport_list[outidx].name = transport_modules_cmd[idx].transport_name;
				transport_list[outidx].id = transport_modules_cmd[idx].transport_id;
			}
			outidx++;
		}
		idx++;
	}

	*transport_list_entries = outidx;

	if (!err)
		errno = 0;
	return err;
}

const char *knet_get_transport_name_by_id(uint8_t transport)
{
	int savederrno = 0;
	const char *name = NULL;

	if (transport == KNET_MAX_TRANSPORTS) {
		errno = EINVAL;
		return name;
	}

	if ((transport_modules_cmd[transport].transport_name) &&
	    (transport_modules_cmd[transport].built_in)) {
		name = transport_modules_cmd[transport].transport_name;
	} else {
		savederrno = ENOENT;
	}

	errno = name ? 0 : savederrno;
	return name;
}

uint8_t knet_get_transport_id_by_name(const char *name)
{
	int savederrno = 0;
	uint8_t err = KNET_MAX_TRANSPORTS;
	int i, found;

	if (!name) {
		errno = EINVAL;
		return err;
	}

	i = 0;
	found = 0;
	while (transport_modules_cmd[i].transport_name != NULL) {
		if (transport_modules_cmd[i].built_in) {
			if (!strcmp(transport_modules_cmd[i].transport_name, name)) {
				err = transport_modules_cmd[i].transport_id;
				found = 1;
				break;
			}
		}
		i++;
	}

	if (!found) {
		savederrno = EINVAL;
	}

	errno = err == KNET_MAX_TRANSPORTS ? savederrno : 0;
	return err;
}

int knet_handle_set_transport_reconnect_interval(knet_handle_t knet_h, uint32_t msecs)
{
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if (!msecs) {
		errno = EINVAL;
		return -1;
	}

	if (msecs < 1000) {
		log_warn(knet_h, KNET_SUB_HANDLE, "reconnect internval below 1 sec (%u msecs) might be too aggressive", msecs);
	}

	if (msecs > 60000) {
		log_warn(knet_h, KNET_SUB_HANDLE, "reconnect internval above 1 minute (%u msecs) could cause long delays in network convergiance", msecs);
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	knet_h->reconnect_int = msecs;

	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = 0;
	return 0;
}

int knet_handle_get_transport_reconnect_interval(knet_handle_t knet_h, uint32_t *msecs)
{
	int savederrno = 0;

	if (!_is_valid_handle(knet_h)) {
		return -1;
	}

	if (!msecs) {
		errno = EINVAL;
		return -1;
	}

	savederrno = pthread_rwlock_rdlock(&knet_h->global_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get read lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	*msecs = knet_h->reconnect_int;

	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = 0;
	return 0;
}
