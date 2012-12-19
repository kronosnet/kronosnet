/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __THREADS_H__
#define __THREADS_H__

#define KNET_EPOLL_MAX_EVENTS 8

void *_handle_tap_to_links_thread(void *data);
void *_handle_recv_from_links_thread(void *data);
void *_handle_heartbt_thread(void *data);
void *_handle_dst_link_handler_thread(void *data);

#endif
