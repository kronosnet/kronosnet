/*
 * Copyright (C) 2016-2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNET_LINKS_ACL_H__
#define __KNET_LINKS_ACL_H__

#include "internals.h"

typedef enum {
	CHECK_TYPE_ADDRESS,
	CHECK_TYPE_MASK,
	CHECK_TYPE_RANGE
} check_type_t;

typedef enum {
	CHECK_ACCEPT,
	CHECK_REJECT
} check_acceptreject_t;

typedef struct {
	uint8_t				transport_proto;

	int (*protocheck_validate)	(void *fd_tracker_match_entry_head, struct sockaddr_storage *checkip);

	int (*protocheck_add)		(void *fd_tracker_match_entry_head,
					 struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
					 check_type_t type, check_acceptreject_t acceptreject);

	int (*protocheck_rm)		(void *fd_tracker_match_entry_head,
					 struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
					 check_type_t type, check_acceptreject_t acceptreject);

	void (*protocheck_rmall)	(void *fd_tracker_match_entry_head);
} check_ops_t;

int check_add(knet_handle_t knet_h, int sock, uint8_t transport,
	      struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
	      check_type_t type, check_acceptreject_t acceptreject);
int check_rm(knet_handle_t knet_h, int sock, uint8_t transport,
	     struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
	     check_type_t type, check_acceptreject_t acceptreject);
void check_rmall(knet_handle_t knet_h, int sock, uint8_t transport);
int check_validate(knet_handle_t knet_h, int sock, uint8_t transport, struct sockaddr_storage *checkip);

#endif
