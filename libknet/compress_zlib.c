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
#include <dlfcn.h>
#ifdef BUILDCOMPZLIB
#include <zlib.h>

#include "internals.h"
#include "compress_zlib.h"
#include "logging.h"

/*
 * global vars for dlopen
 */
static void *zlib_lib;
static int zlib_libref = 0;

/*
 * symbols remapping
 */
int (*_int_uncompress)(Bytef *dest, uLongf *destLen,
		       const Bytef *source, uLong sourceLen);
int (*_int_compress2)(Bytef *dest, uLongf *destLen,
		      const Bytef *source, uLong sourceLen,
		      int level);

static int zlib_remap_symbols(knet_handle_t knet_h)
{
	int err = 0;
	char *error = NULL;

	_int_uncompress = dlsym(zlib_lib, "uncompress");
	if (!_int_uncompress) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_ZLIBCOMP, "unable to map uncompress: %s", error);
		err = -1;
		goto out;
	}

	_int_compress2 = dlsym(zlib_lib, "compress2");
	if (!_int_compress2) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_ZLIBCOMP, "unable to map compress2: %s", error);
		err = -1;
		goto out;
	}

out:
	if (err) {
		_int_uncompress = NULL;
		_int_compress2 = NULL;
		errno = EINVAL;
	}
	return err;
}

int zlib_load_lib(
	knet_handle_t knet_h)
{
	int err = 0, savederrno = 0;
	char *error = NULL;

	if (!zlib_lib) {
		/*
		 * clear any pending error
		 */
		dlerror();

		zlib_lib = dlopen("libz.so.1", RTLD_LAZY | RTLD_GLOBAL);
		error = dlerror();
		if (error != NULL) {
			log_err(knet_h, KNET_SUB_ZLIBCOMP, "unable to dlopen libz.so.1: %s", error);
			savederrno = EAGAIN;
			err = -1;
			goto out;
		}

		if (zlib_remap_symbols(knet_h) < 0) {
			savederrno = errno;
			err = -1;
			goto out;
		}
	}
	zlib_libref++;
out:
	errno = savederrno;
	return err;
}

void zlib_unload_lib(
	knet_handle_t knet_h,
	int force)
{
	zlib_libref--;
	if ((force) || ((zlib_lib) && (zlib_libref == 0))) {
		dlclose(zlib_lib);
		zlib_lib = NULL;
	}
	return;
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
