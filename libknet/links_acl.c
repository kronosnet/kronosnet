/*
 * Copyright (C) 2016-2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "internals.h"
#include "logging.h"
#include "transports.h"
#include "transport_common.h"
#include "links_acl.h"
#include "links_acl_ip.h"

/*
 * all those functions will return errno from the
 * protocol specific functions
 */

int check_add(knet_handle_t knet_h, int sock, uint8_t transport,
	      struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
	      check_type_t type, check_acceptreject_t acceptreject)
{
	int err = -1;

	switch(transport_get_proto(knet_h, transport)) {
		case LOOPBACK:
			errno = 0;
			err = 0;
			break;
		case IP_PROTO:
			err = ipcheck_addip(&knet_h->knet_transport_fd_tracker[sock].match_entry,
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
			errno = 0;
			err = 0;
			break;
		case IP_PROTO:
			err = ipcheck_rmip(&knet_h->knet_transport_fd_tracker[sock].match_entry,
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
			ipcheck_rmall(&knet_h->knet_transport_fd_tracker[sock].match_entry);
			break;
		default:
			break;
	}
}

/*
 * return 0 to reject and 1 to accept a packet
 */
int check_validate(knet_handle_t knet_h, int sock, uint8_t transport, struct sockaddr_storage *checkip)
{
	switch(transport_get_proto(knet_h, transport)) {
		case LOOPBACK:
			errno = 0;
			return 1;
			break;
		case IP_PROTO:
			return ipcheck_validate(&knet_h->knet_transport_fd_tracker[sock].match_entry, checkip);
			break;
		default:
			break;
	}
	/*
	 * reject by default
	 */
	return 0;
}
