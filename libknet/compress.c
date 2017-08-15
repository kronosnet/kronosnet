/*
 * Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "internals.h"
#include "compress.h"
#include "logging.h"

#ifdef BUILDCOMPZLIB
#include "compress_zlib.h"
#endif
#ifdef BUILDCOMPLZ4
#include "compress_lz4.h"
#endif
#ifdef BUILDCOMPLZO2
#include "compress_lzo2.h"
#endif
#ifdef BUILDCOMPLZMA
#include "compress_lzma.h"
#endif
#ifdef BUILDCOMPBZIP2
#include "compress_bzip2.h"
#endif

/*
 * internal module switch data
 */

/*
 * DO NOT CHANGE MODEL_ID HERE OR ONWIRE COMPATIBILITY
 * WILL BREAK!
 *
 * always add before the last NULL/NULL/NULL.
 */

compress_model_t compress_modules_cmds[] = {
	{ 0, 1, "none", NULL, NULL, NULL, NULL, NULL },
#ifdef BUILDCOMPZLIB
	{ 1, 1, "zlib", NULL, NULL, zlib_val_level, zlib_compress, zlib_decompress },
#else
	{ 1, 0, "zlib", NULL, NULL, NULL, NULL, NULL },
#endif
#ifdef BUILDCOMPLZ4
	{ 2, 1, "lz4", NULL, NULL, lz4_val_level, lz4_compress, lz4_decompress },
	{ 3, 1, "lz4hc", NULL, NULL, lz4hc_val_level, lz4hc_compress, lz4_decompress },
#else
	{ 2, 0, "lz4", NULL, NULL, NULL, NULL, NULL },
	{ 3, 0, "lz4hc", NULL, NULL, NULL, NULL, NULL },
#endif
#ifdef BUILDCOMPLZO2
	{ 4, 1, "lzo2", lzo2_init, lzo2_fini, lzo2_val_level, lzo2_compress, lzo2_decompress },
#else
	{ 4, 0, "lzo2", NULL, NULL, NULL, NULL, NULL },
#endif
#ifdef BUILDCOMPLZMA
	{ 5, 1, "lzma", NULL, NULL, lzma_val_level, lzma_compress, lzma_decompress },
#else
	{ 5, 0, "lzma", NULL, NULL, NULL, NULL, NULL },
#endif
#ifdef BUILDCOMPBZIP2
	{ 6, 1, "bzip2", NULL, NULL, bzip2_val_level, bzip2_compress, bzip2_decompress },
#else
	{ 6, 0, "bzip2", NULL, NULL, NULL, NULL, NULL },
#endif
	{ 255, 0, NULL, NULL, NULL, NULL, NULL, NULL },
};

static int get_model(const char *model)
{
	int idx = 0;

	while (compress_modules_cmds[idx].model_name != NULL) {
		if ((!strcmp(compress_modules_cmds[idx].model_name, model)) &&
		    (compress_modules_cmds[idx].built_in == 1)) {
			return compress_modules_cmds[idx].model_id;
		}
		idx++;
	}
	return -1;
}

static int get_max_model(void)
{
	int idx = 0;
	while (compress_modules_cmds[idx].model_name != NULL) {
		idx++;
	}
	return idx - 1;
}

static int is_valid_model(int compress_model)
{
	int idx = 0;

	while (compress_modules_cmds[idx].model_name != NULL) {
		if ((compress_model == compress_modules_cmds[idx].model_id) &&
		    (compress_modules_cmds[idx].built_in == 1)) {
			return 0;
		}
		idx++;
	}
	return -1;
}

static int val_level(
	knet_handle_t knet_h,
	int compress_model,
	int compress_level)
{
	return compress_modules_cmds[compress_model].val_level(knet_h, compress_level);
}

int compress_init(
	knet_handle_t knet_h,
	struct knet_handle_compress_cfg *knet_handle_compress_cfg)
{
	int cmp_model, idx = 0;

	if (get_max_model() > KNET_MAX_COMPRESS_METHODS) {
		log_err(knet_h, KNET_SUB_COMPRESS, "Too many compress methods supported by compress.c. Please complain to knet developers to fix internals.h KNET_MAX_COMPRESS_METHODS define!");
		errno = EINVAL;
		return -1;
	}
	if (!knet_handle_compress_cfg) {
		while ((compress_modules_cmds[idx].model_name != NULL) &&
		       (compress_modules_cmds[idx].built_in == 1)) {
			if (compress_modules_cmds[idx].init != NULL) {
				if (compress_modules_cmds[idx].init(knet_h, idx) < 0) {
					log_err(knet_h, KNET_SUB_COMPRESS, "Failed to initialize %s library", compress_modules_cmds[idx].model_name);
					errno = EINVAL;
					return -1;
				}
			}
			idx++;
		}
		return 0;
	}

	log_debug(knet_h, KNET_SUB_COMPRESS,
		  "Initizializing compress module [%s/%d/%u]",
		  knet_handle_compress_cfg->compress_model, knet_handle_compress_cfg->compress_level, knet_handle_compress_cfg->compress_threshold);

	cmp_model = get_model(knet_handle_compress_cfg->compress_model);
	if (cmp_model < 0) {
		log_err(knet_h, KNET_SUB_COMPRESS, "compress model %s not supported", knet_handle_compress_cfg->compress_model);
		errno = EINVAL;
		return -1;
	}

	if (cmp_model > 0) {
		if (val_level(knet_h, cmp_model, knet_handle_compress_cfg->compress_level) < 0) {
			log_err(knet_h, KNET_SUB_COMPRESS, "compress level %d not supported for model %s",
				knet_handle_compress_cfg->compress_level, knet_handle_compress_cfg->compress_model);
			errno = EINVAL;
			return -1;
		}
		if (knet_handle_compress_cfg->compress_threshold > KNET_MAX_PACKET_SIZE) {
			log_err(knet_h, KNET_SUB_COMPRESS, "compress threshold cannot be higher than KNET_MAX_PACKET_SIZE (%d).",
				 KNET_MAX_PACKET_SIZE);
			errno = EINVAL;
			return -1;
		}
		if (knet_handle_compress_cfg->compress_threshold == 0) {
			knet_h->compress_threshold = KNET_COMPRESS_THRESHOLD;
			log_debug(knet_h, KNET_SUB_COMPRESS, "resetting compression threshold to default (%d)", KNET_COMPRESS_THRESHOLD);
		} else {
			knet_h->compress_threshold = knet_handle_compress_cfg->compress_threshold;
		}
	}

	knet_h->compress_model = cmp_model;
	knet_h->compress_level = knet_handle_compress_cfg->compress_level;

	return 0;
}

void compress_fini(
	knet_handle_t knet_h)
{
	int idx = 0;
	while ((compress_modules_cmds[idx].model_name != NULL) &&
	       (compress_modules_cmds[idx].built_in == 1) &&
	       (idx < KNET_MAX_COMPRESS_METHODS)) {
		if (compress_modules_cmds[idx].fini != NULL) {
			compress_modules_cmds[idx].fini(knet_h, idx);
		}
		idx++;
	}
	return;
}

int compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	return compress_modules_cmds[knet_h->compress_model].compress(knet_h, buf_in, buf_in_len, buf_out, buf_out_len);
}

int decompress(
	knet_handle_t knet_h,
	int compress_model,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	if (is_valid_model(compress_model) < 0) {
		log_err(knet_h,  KNET_SUB_COMPRESS, "This build of libknet does not support %s compression. Please contact your distribution vendor or fix the build", compress_modules_cmds[compress_model].model_name);
		errno = EINVAL;
		return -1;
	}
	return compress_modules_cmds[compress_model].decompress(knet_h, buf_in, buf_in_len, buf_out, buf_out_len);
}
