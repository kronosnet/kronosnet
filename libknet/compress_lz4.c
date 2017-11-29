/*
 * Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <lz4hc.h>

#include "logging.h"
#include "compress_model.h"

static int lz4_val_level(
	knet_handle_t knet_h,
	int compress_level)
{
	if (compress_level <= 0) {
		log_info(knet_h, KNET_SUB_LZ4COMP, "lz4 acceleration level 0 (or negatives) are automatically remapped to 1");
	}

	return 0;
}

static int lz4_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int lzerr = 0, err = 0;
	int savederrno = 0;

	lzerr = LZ4_compress_fast((const char *)buf_in, (char *)buf_out, buf_in_len, KNET_DATABUFSIZE_COMPRESS, knet_h->compress_level);

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

compress_model_t compress_model = { "", 0, 0, 0, NULL, NULL, NULL, lz4_val_level, lz4_compress, lz4_decompress };
