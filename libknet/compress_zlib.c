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
#ifdef BUILDCOMPZLIB
#include <zlib.h>

#include "internals.h"
#include "compress_zlib.h"
#include "logging.h"
#include "common.h"

/*
 * global vars for dlopen
 */
static void *zlib_lib;

#include "compress_zlib_remap.h"

static int zlib_remap_symbols(knet_handle_t knet_h)
{
#define REMAP_WITH(name) remap_symbol (knet_h, KNET_SUB_ZLIBCOMP, zlib_lib, name)
#include "compress_zlib_remap.h"
	return 0;

 fail:
#define REMAP_FAIL
#include "compress_zlib_remap.h"
	errno = EINVAL;
	return -1;
}

int zlib_load_lib(
	knet_handle_t knet_h, compress_model_t *dummy)
{
	int err = 0, savederrno = 0;

	if (!zlib_lib) {
		zlib_lib = open_lib(knet_h, LIBZ_1, 0);
		if (!zlib_lib) {
			savederrno = EAGAIN;
			err = -1;
			goto out;
		}
	}

	if (zlib_remap_symbols(knet_h) < 0) {
		savederrno = errno;
		err = -1;
	}
out:
	errno = savederrno;
	return err;
}

int zlib_val_level(
	knet_handle_t knet_h,
	int compress_level)
{
	if (compress_level < 0) {
		log_err(knet_h, KNET_SUB_ZLIBCOMP, "zlib does not support negative compression level %d",
			 compress_level);
		return -1;
	}
	if (compress_level > 9) {
		log_err(knet_h, KNET_SUB_ZLIBCOMP, "zlib does not support compression level higher than 9");
		return -1;
	}
	if (compress_level == 0) {
		log_warn(knet_h, KNET_SUB_ZLIBCOMP, "zlib compress level 0 does NOT perform any compression");
	}
	return 0;
}

int zlib_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int zerr = 0, err = 0;
	int savederrno = 0;
	uLongf destLen = *buf_out_len;

	zerr = (*_int_compress2)(buf_out, &destLen,
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

int zlib_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int zerr = 0, err = 0;
	int savederrno = 0;
	uLongf destLen = *buf_out_len;

	zerr = (*_int_uncompress)(buf_out, &destLen,
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
#endif
