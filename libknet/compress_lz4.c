/*
 * Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#ifdef BUILDCOMPLZ4
#include <lz4hc.h>

#include "internals.h"
#include "compress_lz4.h"
#include "logging.h"
#include "common.h"

/*
 * global vars for dlopen
 */
static void *lz4_lib;

#include "compress_lz4_remap.h"

static int lz4_remap_symbols(knet_handle_t knet_h)
{
#define REMAP_WITH(name) remap_symbol (knet_h, KNET_SUB_LZ4COMP, lz4_lib, name)
#include "compress_lz4_remap.h"
	return 0;

 fail:
#define REMAP_FAIL
#include "compress_lz4_remap.h"
	errno = EINVAL;
	return -1;
}

int lz4_load_lib(
	knet_handle_t knet_h)
{
	int err = 0, savederrno = 0;

	if (!lz4_lib) {
		lz4_lib = open_lib(knet_h, LIBLZ4_1, 0);
		if (!lz4_lib) {
			savederrno = EAGAIN;
			err = -1;
			goto out;
		}
	}

	if (lz4_remap_symbols(knet_h) < 0) {
		savederrno = errno;
		err = -1;
	}
out:
	errno = savederrno;
	return err;
}

int lz4_val_level(
	knet_handle_t knet_h,
	int compress_level)
{
	if (compress_level <= 0) {
		log_info(knet_h, KNET_SUB_LZ4COMP, "lz4 acceleration level 0 (or negatives) are automatically remapped to 1 by %s", LIBLZ4_1);
	}

	return 0;
}

int lz4_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int lzerr = 0, err = 0;
	int savederrno = 0;

	lzerr = (*_int_LZ4_compress_fast)((const char *)buf_in, (char *)buf_out, buf_in_len, KNET_DATABUFSIZE_COMPRESS, knet_h->compress_level);

	/*
	 * data compressed
	 */
        if (lzerr > 0) {
		*buf_out_len = lzerr;
	}

	/*
	 * unable to compress
	 */
	if (lzerr == 0) {
		*buf_out_len = buf_in_len;
	}

	/*
	 * lz4 internal error
	 */
	if (lzerr < 0) {
		log_err(knet_h, KNET_SUB_LZ4COMP, "lz4 compression error: %d", lzerr);
		savederrno = EINVAL;
		err = -1;
	}

	errno = savederrno;
	return err;
}

#ifdef LZ4HC_CLEVEL_MAX
#define KNET_LZ4HC_MAX LZ4HC_CLEVEL_MAX
#endif
#ifdef LZ4HC_MAX_CLEVEL
#define KNET_LZ4HC_MAX LZ4HC_MAX_CLEVEL
#endif
#ifndef KNET_LZ4HC_MAX
#define KNET_LZ4HC_MAX 0
#error Please check lz4hc.h for missing LZ4HC_CLEVEL_MAX or LZ4HC_MAX_CLEVEL variants
#endif

int lz4hc_val_level(
	knet_handle_t knet_h,
	int compress_level)
{
	if (compress_level < 1) {
		log_err(knet_h, KNET_SUB_LZ4HCCOMP, "lz4hc supports only 1+ values for compression level");
		errno = EINVAL;
		return -1;
	}

	if (compress_level < 4) {
		log_info(knet_h, KNET_SUB_LZ4HCCOMP, "lz4hc recommends 4+ compression level for better results");
	}

	if (compress_level > KNET_LZ4HC_MAX) {
		log_warn(knet_h, KNET_SUB_LZ4HCCOMP, "lz4hc installed on this system supports up to compression level %d. Higher values behaves as %d", KNET_LZ4HC_MAX, KNET_LZ4HC_MAX);
	}

	return 0;
}

int lz4hc_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int lzerr = 0, err = 0;
	int savederrno = 0;

	lzerr = (*_int_LZ4_compress_HC)((const char *)buf_in, (char *)buf_out, buf_in_len, KNET_DATABUFSIZE_COMPRESS, knet_h->compress_level);

	/*
	 * data compressed
	 */
        if (lzerr > 0) {
		*buf_out_len = lzerr;
	}

	/*
	 * unable to compress
	 */
	if (lzerr <= 0) {
		log_err(knet_h, KNET_SUB_LZ4HCCOMP, "lz4hc compression error: %d", lzerr);
		savederrno = EINVAL;
		err = -1;
	}

	errno = savederrno;
	return err;
}

int lz4_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int lzerr = 0, err = 0;
	int savederrno = 0;

	lzerr = (*_int_LZ4_decompress_safe)((const char *)buf_in, (char *)buf_out, buf_in_len, KNET_DATABUFSIZE);

	if (lzerr < 0) {
		log_err(knet_h, KNET_SUB_LZ4COMP, "lz4 decompression error: %d", lzerr);
		savederrno = EINVAL;
		err = -1;
	}

	if (lzerr > 0) {
		*buf_out_len = lzerr;
	}

	errno = savederrno;
	return err;
}
#endif
