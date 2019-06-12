/*
 * Copyright (C) 2010-2019 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+
 */

#ifndef __KNETD_VTY_UTILS_H__
#define __KNETD_VTY_UTILS_H__

#include "vty.h"

#define VTY_MAX_BUFFER_SIZE	4096

int knet_vty_write(struct knet_vty *vty, const char *format, ...)
		   __attribute__ ((__format__ (__printf__, 2, 3)));

int knet_vty_read(struct knet_vty *vty, unsigned char *buf, size_t bufsize);

int knet_vty_set_echo(struct knet_vty *vty, int on);

void knet_vty_print_banner(struct knet_vty *vty);

int knet_vty_set_iacs(struct knet_vty *vty);

void knet_vty_free_history(struct knet_vty *vty);

void knet_vty_exit_node(struct knet_vty *vty);

int knet_vty_is_line_empty(struct knet_vty *vty);

void knet_vty_prompt(struct knet_vty *vty);

#endif
