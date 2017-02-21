/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNETD_VTY_H__
#define __KNETD_VTY_H__

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "libknet.h"

#define KNET_VTY_DEFAULT_PORT		50000

#define KNET_VTY_DEFAULT_MAX_CONN	4
#define KNET_VTY_TOTAL_MAX_CONN		16
#define KNET_VTY_CLI_TIMEOUT		300

#define KNET_VTY_MAX_LINE		512

#define KNET_VTY_MAX_HIST		50

struct knet_vty_global_conf {
	int	idle_timeout;
};

struct knet_vty {
	pthread_t		vty_thread;	/* thread struct for this vty */
	struct sockaddr_storage	src_sa;		/* source IP */
	socklen_t		src_sa_len;	/* sa len */
	char			ip[128];	/* ip addr of source */
	char			username[64];	/* username */
	char			line[KNET_VTY_MAX_LINE]; /* input line */
	char			*history[KNET_VTY_MAX_HIST]; /* history */
	int			history_idx;	/* index to history */
	int			history_pos;	/* position in the history */
	int			insert_mode;	/* add or insert */
	int			line_idx;	/* index on the input line */
	int			cursor_pos;	/* position of the cursor in the line */
	int			escape;		/* escape status */
	int			escape_code;	/* escape code buffer */
	int			user_can_enable;/* user is in group kronosnetadm */
	int			vty_sock;	/* tcp socket for this vty */
	int			conn_num;	/* vty number */
	int			active;		/* vty is active */
	int			got_epipe;	/* vty_sock has been closed */
	int			idle;		/* idle time */
	int			idle_timeout;	/* in seconds or 0 to disable automatic logout */
	int			node;		/* node number of the menus */
	int			prevnode;	/* node number of the menus (used by VTY node) */
	void			*param;		/* pointer to cmd param */
	int			paramoffset;	/* required if param is set */
	int			logfd;		/* fd to pass to iface create */
	int			loglevel;	/* loglevel (debug, etc) */
	void			*iface;		/* pointer to iface we are working on */
	knet_node_id_t		host_id;	/* peer/host we are working on */
	uint8_t			link_id;	/* link id we are working on */
	int			filemode;	/* tell print_conf to add or not carriage return */
	struct knet_vty_global_conf *vty_global_conf; /* pointer to vty global config */
};

extern pthread_mutex_t knet_vty_mutex;
extern int knet_vty_config;

extern struct knet_vty knet_vtys[KNET_VTY_TOTAL_MAX_CONN];

int knet_vty_main_loop(int debug);

#endif
