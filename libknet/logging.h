/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __LOGGING_H__
#define __LOGGING_H__

void log_msg(knet_handle_t knet_h, uint8_t subsystem, uint8_t msglevel,
	     const char *fmt, ...) __attribute__((format(printf, 4, 5)));;

#define log_err(knet_h, subsys, fmt, args...) log_msg(knet_h, subsys, KNET_LOG_ERR, fmt, ##args)
#define log_warn(knet_h, subsys, fmt, args...) log_msg(knet_h, subsys, KNET_LOG_WARN, fmt, ##args)
#define log_info(knet_h, subsys, fmt, args...) log_msg(knet_h, subsys, KNET_LOG_INFO, fmt, ##args)
#define log_debug(knet_h, subsys, fmt, args...) log_msg(knet_h, subsys, KNET_LOG_DEBUG, fmt, ##args)

#endif
