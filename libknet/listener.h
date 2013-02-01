/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __LISTENER_H__
#define __LISTENER_H__

#include "internals.h"

int _listener_add(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id);
int _listener_remove(knet_handle_t knet_h, uint16_t host_id, uint8_t link_id);

#endif
