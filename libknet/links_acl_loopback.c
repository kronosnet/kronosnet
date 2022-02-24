/*
 * Copyright (C) 2019-2022 Red Hat, Inc.  All rights reserved.
 *
 * Author: Christine Caulfield <ccaulfie@redhat.com>
 *
 * This software licensed under LGPL-2.0+
 */

#include "config.h"

#include <errno.h>

#include "internals.h"
#include "logging.h"
#include "transports.h"
#include "links_acl.h"
#include "links_acl_loopback.h"

int loopbackcheck_validate(void *fd_tracker_match_entry_head, struct sockaddr_storage *checkip)
{
	return 1;
}

void loopbackcheck_rmall(void *fd_tracker_match_entry_head)
{
	return;
}

int loopbackcheck_rm(void *fd_tracker_match_entry_head,
		     struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
		     check_type_t type, check_acceptreject_t acceptreject)
{
	return 0;
}

int loopbackcheck_add(void *fd_tracker_match_entry_head, int index,
		      struct sockaddr_storage *ss1, struct sockaddr_storage *ss2,
		      check_type_t type, check_acceptreject_t acceptreject)
{
	return 0;
}
