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

int check_add(knet_handle_t knet_h, int sock, uint8_t transport,
	      struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
	      check_type_t type, check_acceptreject_t acceptreject);
int check_rm(knet_handle_t knet_h, int sock, uint8_t transport,
	     struct sockaddr_storage *ip1, struct sockaddr_storage *ip2,
	     check_type_t type, check_acceptreject_t acceptreject);
void check_rmall(knet_handle_t knet_h, int sock, uint8_t transport);
int _link_add_default_acl(knet_handle_t knet_h, struct knet_link *kh_link);
int _link_rm_default_acl(knet_handle_t knet_h, struct knet_link *kh_link);
int _generic_filter_packet_by_acl(knet_handle_t knet_h, int sockfd, struct sockaddr_storage *checkip);

#endif
