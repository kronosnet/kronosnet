/*
 * Copyright (C) 2012-2017 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNET_LOGGING_H__
#define __KNET_LOGGING_H__

#include "internals.h"

typedef void log_msg_t(knet_handle_t knet_h, uint8_t subsystem, uint8_t msglevel,
		       const char *fmt, ...) __attribute__((format(printf, 4, 5)));

#ifdef KNET_MODULE
#define LOG_MSG (*log_msg)
#else
#define LOG_MSG log_msg
#endif

log_msg_t LOG_MSG;

#define log_err(knet_h, subsys, fmt, args...) \
	LOG_MSG(knet_h, subsys, KNET_LOG_ERR, fmt, ##args)

#define log_warn(knet_h, subsys, fmt, args...) \
	LOG_MSG(knet_h, subsys, KNET_LOG_WARN, fmt, ##args)

#define log_info(knet_h, subsys, fmt, args...) \
	LOG_MSG(knet_h, subsys, KNET_LOG_INFO, fmt, ##args)

#define log_debug(knet_h, subsys, fmt, args...) \
	LOG_MSG(knet_h, subsys, KNET_LOG_DEBUG, fmt, ##args)

#endif
