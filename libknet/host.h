/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __HOST_H__
#define __HOST_H__

#include "internals.h"

int _seq_num_lookup(struct knet_host *host, seq_num_t seq_num, int defrag_buf, int clear_buf);
void _seq_num_set(struct knet_host *host, seq_num_t seq_num, int defrag_buf);

int _send_host_info(knet_handle_t knet_h, const void *data, const size_t datalen);
int _host_dstcache_update_async(knet_handle_t knet_h, struct knet_host *host);
int _host_dstcache_update_sync(knet_handle_t knet_h, struct knet_host *host);

#endif
