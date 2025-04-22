/*
 * Copyright (C) 2019-2025 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_LINKS_ACL_LOOPBACK_H__
#define __KNET_LINKS_ACL_LOOPBACK_H__

#include "internals.h"
#include "links_acl.h"

int loopbackcheck_validate(void *fd_tracker_match_entry_head, struct sockaddr_storage *checkip);

int loopbackcheck_add(void *fd_tracker_match_entry_head, int index,
		      struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
		      check_type_t type, check_acceptreject_t acceptreject);

int loopbackcheck_rm(void *fd_tracker_match_entry_head,
		     struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
		     check_type_t type, check_acceptreject_t acceptreject);

void loopbackcheck_rmall(void *fd_tracker_match_entry_head);

#endif
