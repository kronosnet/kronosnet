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

int _should_deliver(struct knet_host *host, int bcast, seq_num_t seq_num, int defrag_buf);
void _has_been_delivered(struct knet_host *host, int bcast, seq_num_t seq_num);
void _has_been_seen(struct knet_host *host, int bcast, seq_num_t seq_num);
int _send_host_info(knet_handle_t knet_h, const void *data, const size_t datalen);
int _host_dstcache_update_async(knet_handle_t knet_h, struct knet_host *host);
int _host_dstcache_update_sync(knet_handle_t knet_h, struct knet_host *host);

#endif
