/*
 * Copyright (C) 2017-2025 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */
#define KNET_MODULE

#include "config.h"

#include <errno.h>
#include <lz4.h>
#include <lz4hc.h>

#include "logging.h"
#include "compress_model.h"

#ifdef LZ4HC_CLEVEL_DEFAULT
#define KNET_COMPRESS_DEFAULT LZ4HC_CLEVEL_DEFAULT /* lz4hc default compression level from lz4hc.h */
#else
#define KNET_COMPRESS_DEFAULT KNET_COMPRESS_UNKNOWN_DEFAULT
#endif
#ifdef LZ4HC_CLEVEL_MAX
#define KNET_LZ4HC_MAX LZ4HC_CLEVEL_MAX
#endif
#ifdef LZ4HC_MAX_CLEVEL
#define KNET_LZ4HC_MAX LZ4HC_MAX_CLEVEL
#endif
#ifndef KNET_LZ4HC_MAX
/*
 * older releases of lz4 do not define LZ4HC_CLEVEL range.
 * According to lz4hc.h, any value between 0 and 16 is valid.
 * We defalt to 16 based on the comments in the include file
 * from older versions.
 */
#define KNET_LZ4HC_MAX 16
#endif

static int lz4hc_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int lzerr = 0, err = 0;
	int savederrno = 0;

	lzerr = LZ4_compress_HC((const char *)buf_in, (char *)buf_out, buf_in_len, KNET_DATABUFSIZE_COMPRESS, knet_h->compress_level);

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

/* This is a straight copy from compress_lz4.c */
static int lz4_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int lzerr = 0, err = 0;
	int savederrno = 0;

	lzerr = LZ4_decompress_safe((const char *)buf_in, (char *)buf_out, buf_in_len, KNET_DATABUFSIZE);

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

static int lz4hc_get_default_level()
{
	return KNET_COMPRESS_DEFAULT;
}

compress_ops_t compress_model = {
	KNET_COMPRESS_MODEL_ABI,
	NULL,
	NULL,
	NULL,
	NULL,
	lz4hc_compress,
	lz4_decompress,
	lz4hc_get_default_level
};
