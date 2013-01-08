/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>

#include "internals.h"
#include "logging.h"

struct pretty_names {
	const char *name;
	uint8_t val;
};

static struct pretty_names subsystem_names[] =
{
	{ "common", KNET_SUB_COMMON },
	{ "handle", KNET_SUB_HANDLE },
	{ "host", KNET_SUB_HOST },
	{ "listener", KNET_SUB_LISTENER },
	{ "link", KNET_SUB_LINK },
	{ "tap_t", KNET_SUB_TAP_T },
	{ "link_t", KNET_SUB_LINK_T },
	{ "hb_t", KNET_SUB_HB_T },
	{ "switch_t", KNET_SUB_SWITCH_T },
	{ "filter", KNET_SUB_FILTER },
	{ "crypto", KNET_SUB_CRYPTO },
	{ "nsscrypto", KNET_SUB_NSSCRYPTO }
};

const char *knet_get_subsystem_name(uint8_t subsystem)
{
	unsigned int i;

	for (i = 0; subsystem_names[i].val <= KNET_MAX_SUBSYSTEMS; i++) {
		if (subsystem_names[i].val == subsystem) {
			return subsystem_names[i].name;
		}
	}
	return "unknown";
}

uint8_t knet_get_subsystem_id(const char *name)
{
	unsigned int i;

	for (i = 0; subsystem_names[i].val <= KNET_MAX_SUBSYSTEMS; i++) {
		if (strcasecmp(name, subsystem_names[i].name) == 0) {
			return subsystem_names[i].val;
		}
	}
	return KNET_SUB_COMMON;
}

static struct pretty_names loglevel_names[] =
{
	{ "ERROR", KNET_LOG_ERR },
	{ "WARNING", KNET_LOG_WARN },
	{ "info", KNET_LOG_INFO },
	{ "debug", KNET_LOG_DEBUG }
};

const char *knet_get_loglevel_name(uint8_t level)
{
	unsigned int i;

	for (i = 0; loglevel_names[i].val <= KNET_LOG_DEBUG; i++) {
		if (loglevel_names[i].val == level) {
			return loglevel_names[i].name;
		}
	}
	return "unknown";
}

uint8_t knet_get_loglevel_id(const char *name)
{
	unsigned int i;

	for (i = 0; loglevel_names[i].val <= (KNET_LOG_DEBUG + 1); i++) {
		if (strcasecmp(name, loglevel_names[i].name) == 0) {
			return loglevel_names[i].val;
		}
	}
	return KNET_LOG_ERR;
}

void knet_set_log_level(knet_handle_t knet_h, uint8_t subsystem, uint8_t level)
{
	if ((!knet_h) ||
	    (subsystem > KNET_SUB_LAST) ||
	    (level > KNET_LOG_DEBUG))
		return;

	knet_h->log_levels[subsystem] = level;
}

void log_msg(knet_handle_t knet_h, uint8_t subsystem, uint8_t msglevel,
	     const char *fmt, ...)
{
	va_list ap;
	struct knet_log_msg msg;
	size_t byte_cnt = 0;
	int len, err;

	if ((knet_h->logfd <= 0) ||
	    (msglevel > knet_h->log_levels[subsystem]))
			return;

	memset(&msg, 0, sizeof(struct knet_log_msg));
	msg.subsystem = subsystem;
	msg.msglevel = msglevel;

	err = pthread_rwlock_rdlock(&knet_h->list_rwlock);
	if ((err == EINVAL) && (knet_h->lock_init_done))
		return;

	va_start(ap, fmt);
	vsnprintf(msg.msg, sizeof(msg.msg) - 1, fmt, ap);
	va_end(ap);

	if (!err)
		pthread_rwlock_unlock(&knet_h->list_rwlock);

	while (byte_cnt < sizeof(struct knet_log_msg)) {
		len = write(knet_h->logfd, &msg, sizeof(struct knet_log_msg) - byte_cnt);
		if (len <= 0)
			return;

		byte_cnt += len;
	}

	return;
}
