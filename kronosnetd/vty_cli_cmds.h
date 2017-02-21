/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNETD_VTY_CLI_CMDS_H__
#define __KNETD_VTY_CLI_CMDS_H__

#include "vty.h"

typedef struct {
	const int		param;
} vty_param_t;

typedef struct {
	const char		*cmd;
	const char		*help;
	const vty_param_t	*params;
	int (*func) (struct knet_vty *vty);
} vty_node_cmds_t;

typedef struct {
	const int		node_num;
	const char		*prompt;
	const vty_node_cmds_t	*cmds;
	const vty_node_cmds_t	*no_cmds;
} vty_nodes_t;

enum vty_nodes {
	NODE_ROOT = 0,
	NODE_CONFIG,
	NODE_INTERFACE,
	NODE_PEER,
	NODE_LINK,
	NODE_VTY
};

int knet_vty_execute_cmd(struct knet_vty *vty);
void knet_vty_help(struct knet_vty *vty);
void knet_vty_tab_completion(struct knet_vty *vty);

int knet_read_conf(void);
void knet_close_down(void);

extern vty_nodes_t knet_vty_nodes[];

#endif
