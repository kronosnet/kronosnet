/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNET_LINK_H__
#define __KNET_LINK_H__

#include "internals.h"

#define KNET_LINK_STATIC             0 /* link has static ip on both ends */
#define KNET_LINK_DYNIP              1 /* link has dynamic destination ip */

int _link_updown(knet_handle_t knet_h, knet_node_id_t node_id, uint8_t link_id,
		 unsigned int enabled, unsigned int connected);

void _link_clear_stats(knet_handle_t knet_h);

#endif
