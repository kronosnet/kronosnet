/*
 * Copyright (C) 2016-2019 Red Hat, Inc.  All rights reserved.
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

struct acl_match_entry {
	check_type_t type;
	check_acceptreject_t acceptreject;
	struct sockaddr_storage addr1; /* Actual IP address, mask top or low IP */
	struct sockaddr_storage addr2; /* high IP address or address bitmask */
	struct acl_match_entry *next;
};

int check_add(knet_handle_t knet_h, int sock, uint8_t transport,
	      struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
	      check_type_t type, check_acceptreject_t acceptreject);
int check_rm(knet_handle_t knet_h, int sock, uint8_t transport,
	     struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
	     check_type_t type, check_acceptreject_t acceptreject);
void check_rmall(knet_handle_t knet_h, int sock, uint8_t transport);
int check_validate(knet_handle_t knet_h, int sockfd, struct sockaddr_storage *checkip);

int _link_add_default_acl(knet_handle_t knet_h, struct knet_link *kh_link);
int _link_rm_default_acl(knet_handle_t knet_h, struct knet_link *kh_link);

#endif
