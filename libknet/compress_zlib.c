/*
 * Copyright (C) 2017-2020 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */
#define KNET_MODULE

#include "config.h"

#include <errno.h>
#include <zlib.h>

#include "logging.h"
#include "compress_model.h"

#ifdef Z_DEFAULT_COMPRESSION
#define KNET_COMPRESS_DEFAULT Z_DEFAULT_COMPRESSION /* zlib default compression level from zlib.h */
#else
#define KNET_COMPRESS_DEFAULT KNET_COMPRESS_UNKNOWN_DEFAULT
#endif

static int zlib_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int zerr = 0, err = 0;
	int savederrno = 0;
	uLongf destLen = *buf_out_len;

	zerr = compress2(buf_out, &destLen,
			 buf_in, buf_in_len,
			 knet_h->compress_level);

	*buf_out_len = destLen;

	switch(zerr) {
		case Z_OK:
			err = 0;
			savederrno = 0;
			break;
		case Z_MEM_ERROR:
			log_err(knet_h, KNET_SUB_ZLIBCOMP, "zlib compress mem error");
			err = -1;
			savederrno = ENOMEM;
			break;
		case Z_BUF_ERROR:
			log_err(knet_h, KNET_SUB_ZLIBCOMP, "zlib compress buf error");
			err = -1;
			savederrno = ENOBUFS;
			break;
		case Z_STREAM_ERROR:
			log_err(knet_h, KNET_SUB_ZLIBCOMP, "zlib compress stream error");
			err = -1;
			savederrno = EINVAL;
			break;
		default:
			log_err(knet_h, KNET_SUB_ZLIBCOMP, "zlib unknown compress error: %d", zerr);
			break;
	}

	errno = savederrno;
	return err;
}

static int zlib_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int zerr = 0, err = 0;
	int savederrno = 0;
	uLongf destLen = *buf_out_len;

	zerr = uncompress(buf_out, &destLen,
			  buf_in, buf_in_len);

	*buf_out_len = destLen;

	switch(zerr) {
		case Z_OK:
			err = 0;
			savederrno = 0;
			break;
		case Z_MEM_ERROR:
			log_err(knet_h, KNET_SUB_ZLIBCOMP, "zlib decompress mem error");
			err = -1;
			savederrno = ENOMEM;
			break;
		case Z_BUF_ERROR:
			log_err(knet_h, KNET_SUB_ZLIBCOMP, "zlib decompress buf error");
			err = -1;
			savederrno = ENOBUFS;
			break;
		case Z_DATA_ERROR:
			log_err(knet_h, KNET_SUB_ZLIBCOMP, "zlib decompress data error");
			err = -1;
			savederrno = EINVAL;
			break;
		default:
			log_err(knet_h, KNET_SUB_ZLIBCOMP, "zlib unknown decompress error: %d", zerr);
			break;
	}

	errno = savederrno;
	return err;
}

static int zlib_get_default_level()
{
	return KNET_COMPRESS_DEFAULT;
}

compress_ops_t compress_model = {
	KNET_COMPRESS_MODEL_ABI,
	NULL,
	NULL,
	NULL,
	NULL,
	zlib_compress,
	zlib_decompress,
	zlib_get_default_level
};
