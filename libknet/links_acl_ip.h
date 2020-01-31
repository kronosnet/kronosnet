/*
 * Copyright (C) 2016-2020 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_LINKS_ACL_IP_H__
#define __KNET_LINKS_ACL_IP_H__

#include "internals.h"
#include "links_acl.h"

int ipcheck_validate(void *fd_tracker_match_entry_head, struct sockaddr_storage *checkip);

int ipcheck_addip(void *fd_tracker_match_entry_head, int index,
		  struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
		  check_type_t type, check_acceptreject_t acceptreject);

int ipcheck_rmip(void *fd_tracker_match_entry_head,
		 struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
		 check_type_t type, check_acceptreject_t acceptreject);

void ipcheck_rmall(void *fd_tracker_match_entry_head);

#endif
