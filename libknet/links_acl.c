/*
 * Copyright (C) 2016-2019 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "internals.h"
#include "logging.h"
#include "transports.h"
#include "transport_common.h"
#include "links_acl.h"
#include "links_acl_ip.h"

int check_add(knet_handle_t knet_h, int sock, uint8_t transport,
	      struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
	      check_type_t type, check_acceptreject_t acceptreject)
{
	int err = -1;

	switch(transport_get_proto(knet_h, transport)) {
		case LOOPBACK:
			err = 0;
			break;
		case IP_PROTO:
			err = ipcheck_addip((struct acl_match_entry **)&knet_h->knet_transport_fd_tracker[sock].match_entry,
					    ip1, ip2, type, acceptreject);
			break;
		default:
			break;
	}
	return err;
}

int check_rm(knet_handle_t knet_h, int sock, uint8_t transport,
	     struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
	     check_type_t type, check_acceptreject_t acceptreject)
{
	int err = -1;

	switch(transport_get_proto(knet_h, transport)) {
		case LOOPBACK:
			err = 0;
			break;
		case IP_PROTO:
			err = ipcheck_rmip((struct acl_match_entry **)&knet_h->knet_transport_fd_tracker[sock].match_entry,
					   ip1, ip2, type, acceptreject);
			break;
		default:
			break;
	}
	return err;
}

void check_rmall(knet_handle_t knet_h, int sock, uint8_t transport)
{
	switch(transport_get_proto(knet_h, transport)) {
		case LOOPBACK:
			return;
			break;
		case IP_PROTO:
			ipcheck_rmall((struct acl_match_entry **)&knet_h->knet_transport_fd_tracker[sock].match_entry);
			break;
		default:
			break;
	}
}

int _link_add_default_acl(knet_handle_t knet_h, struct knet_link *kh_link)
{
	return check_add(knet_h, kh_link->outsock, kh_link->transport_type,
			&kh_link->dst_addr, &kh_link->dst_addr, CHECK_TYPE_ADDRESS, CHECK_ACCEPT);
}

int _link_rm_default_acl(knet_handle_t knet_h, struct knet_link *kh_link)
{
	return check_rm(knet_h, kh_link->outsock, kh_link->transport_type,
			&kh_link->dst_addr, &kh_link->dst_addr, CHECK_TYPE_ADDRESS, CHECK_ACCEPT);
}

/*
 * return 0 to reject and 1 to accept a packet
 */
int _generic_filter_packet_by_acl(knet_handle_t knet_h, int sockfd, struct sockaddr_storage *checkip)
{
	switch(transport_get_proto(knet_h, knet_h->knet_transport_fd_tracker[sockfd].transport)) {
		case LOOPBACK:
			return 1;
			break;
		case IP_PROTO:
			return ipcheck_validate((struct acl_match_entry **)&knet_h->knet_transport_fd_tracker[sockfd].match_entry, checkip);
			break;
		default:
			break;
	}
	/*
	 * reject by default
	 */
	return 0;
}
