/*
 * Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */
#define KNET_MODULE

#include "config.h"

#include <errno.h>
#include <lzma.h>

#include "logging.h"
#include "compress_model.h"

static int lzma_val_level(
	knet_handle_t knet_h,
	int compress_level)
{
	if ((compress_level < 0) || (compress_level > 9)) {
                log_err(knet_h, KNET_SUB_LZMACOMP, "lzma unsupported compression preset %d (accepted values from 0 to 9)", compress_level);
		errno = EINVAL;
		return -1;
	}

	return 0;
}

static int lzma_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int err = 0;
	int savederrno = 0;
	size_t out_pos = 0;
	lzma_ret ret = 0;

	ret = lzma_easy_buffer_encode(knet_h->compress_level, LZMA_CHECK_NONE, NULL,
				      (const uint8_t *)buf_in, buf_in_len,
				      (uint8_t *)buf_out, &out_pos, KNET_DATABUFSIZE_COMPRESS);

	switch(ret) {
		case LZMA_OK:
			*buf_out_len = out_pos;
			break;
		case LZMA_MEM_ERROR:
			log_err(knet_h, KNET_SUB_LZMACOMP, "lzma compress memory allocation failed");
			savederrno = ENOMEM;
			err = -1;
			break;
		case LZMA_MEMLIMIT_ERROR:
			log_err(knet_h, KNET_SUB_LZMACOMP, "lzma compress requires higher memory boundaries (see lzma_memlimit_set)");
			savederrno = ENOMEM;
			err = -1;
			break;
		case LZMA_PROG_ERROR:
			log_err(knet_h, KNET_SUB_LZMACOMP, "lzma compress has been called with incorrect options");
			savederrno = EINVAL;
			err = -1;
			break;
		default:
			log_err(knet_h, KNET_SUB_LZMACOMP, "lzma compress unknown error %u", ret);
			savederrno = EINVAL;
			err = -1;
			break;
	}

	errno = savederrno;
	return err;
}

static int lzma_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int err = 0;
	int savederrno = 0;
	uint64_t memlimit = UINT64_MAX; /* disable lzma internal memlimit check */
	size_t out_pos = 0, in_pos = 0;
	lzma_ret ret = 0;

	ret = lzma_stream_buffer_decode(&memlimit, 0, NULL,
					(const uint8_t *)buf_in, &in_pos, buf_in_len,
					(uint8_t *)buf_out, &out_pos, KNET_DATABUFSIZE_COMPRESS);

	switch(ret) {
		case LZMA_OK:
			*buf_out_len = out_pos;
			break;
		case LZMA_MEM_ERROR:
			log_err(knet_h, KNET_SUB_LZMACOMP, "lzma decompress memory allocation failed");
			savederrno = ENOMEM;
			err = -1;
			break;
		case LZMA_MEMLIMIT_ERROR:
			log_err(knet_h, KNET_SUB_LZMACOMP, "lzma decompress requires higher memory boundaries (see lzma_memlimit_set)");
			savederrno = ENOMEM;
			err = -1;
			break;
		case LZMA_DATA_ERROR:
		case LZMA_FORMAT_ERROR:
			log_err(knet_h, KNET_SUB_LZMACOMP, "lzma decompress invalid data received");
			savederrno = EINVAL;
			err = -1;
			break;
		case LZMA_PROG_ERROR:
			log_err(knet_h, KNET_SUB_LZMACOMP, "lzma decompress has been called with incorrect options");
			savederrno = EINVAL;
			err = -1;
			break;
		default:
			log_err(knet_h, KNET_SUB_LZMACOMP, "lzma decompress unknown error %u", ret);
			savederrno = EINVAL;
			err = -1;
			break;
	}

	errno = savederrno;
	return err;
}

compress_ops_t compress_model = {
	KNET_COMPRESS_MODEL_ABI,
	NULL,
	NULL,
	NULL,
	lzma_val_level,
	lzma_compress,
	lzma_decompress
};
