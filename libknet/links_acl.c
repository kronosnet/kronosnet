/*
 * Copyright (C) 2016-2021 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under LGPL-2.0+
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
#include "links_acl_loopback.h"

static check_ops_t proto_check_modules_cmds[] = {
	{ TRANSPORT_PROTO_LOOPBACK, loopbackcheck_validate, loopbackcheck_add, loopbackcheck_rm, loopbackcheck_rmall },
	{ TRANSPORT_PROTO_IP_PROTO, ipcheck_validate, ipcheck_addip, ipcheck_rmip, ipcheck_rmall }
};

/*
 * all those functions will return errno from the
 * protocol specific functions
 */

int check_add(knet_handle_t knet_h, struct knet_link *kn_link,
	      int index,
	      struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
	      check_type_t type, check_acceptreject_t acceptreject)
{
	return proto_check_modules_cmds[transport_get_proto(knet_h, kn_link->transport)].protocheck_add(
			&kn_link->access_list_match_entry_head, index,
			ss1, ss2, type, acceptreject);
}

int check_rm(knet_handle_t knet_h, struct knet_link *kn_link,
	     struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
	     check_type_t type, check_acceptreject_t acceptreject)
{
	return proto_check_modules_cmds[transport_get_proto(knet_h, kn_link->transport)].protocheck_rm(
			&kn_link->access_list_match_entry_head,
			ss1, ss2, type, acceptreject);
}

void check_rmall(knet_handle_t knet_h, struct knet_link *kn_link)
{
	proto_check_modules_cmds[transport_get_proto(knet_h, kn_link->transport)].protocheck_rmall(
		&kn_link->access_list_match_entry_head);
}

/*
 * return 0 to reject and 1 to accept a packet
 */
int check_validate(knet_handle_t knet_h, struct knet_link *kn_link,
		   struct sockaddr_storage *checkip)
{
	return proto_check_modules_cmds[transport_get_proto(knet_h, kn_link->transport)].protocheck_validate(
			&kn_link->access_list_match_entry_head, checkip);
}
