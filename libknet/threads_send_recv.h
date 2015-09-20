/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __THREADS_SEND_RECV_H__
#define __THREADS_SEND_RECV_H__

void *_handle_send_to_links_thread(void *data);
void *_handle_recv_from_links_thread(void *data);

#endif
