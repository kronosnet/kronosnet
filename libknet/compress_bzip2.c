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
#ifdef BUILDCOMPBZIP2
#include <bzlib.h>

#include "internals.h"
#include "compress_bzip2.h"
#include "logging.h"
#include "common.h"

/*
 * global vars for dlopen
 */
static void *bzip2_lib;

/*
 * symbols remapping
 */
int (*_int_BZ2_bzBuffToBuffCompress)(char* dest, unsigned int* destLen,
				     char* source, unsigned int sourceLen,
				     int blockSize100k, int verbosity,
				     int workFactor);
int (*_int_BZ2_bzBuffToBuffDecompress)(char* dest, unsigned int* destLen,
				       char* source, unsigned int sourceLen,
				       int samll, int verbosity);

static int bzip2_remap_symbols(knet_handle_t knet_h)
{
	int err = 0;
	char *error = NULL;

	_int_BZ2_bzBuffToBuffCompress = dlsym(bzip2_lib, "BZ2_bzBuffToBuffCompress");
	if (!_int_BZ2_bzBuffToBuffCompress) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_BZIP2COMP, "unable to map BZ2_bzBuffToBuffCompress: %s", error);
		err = -1;
		goto out;
	}

	_int_BZ2_bzBuffToBuffDecompress = dlsym(bzip2_lib, "BZ2_bzBuffToBuffDecompress");
	if (!_int_BZ2_bzBuffToBuffDecompress) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_BZIP2COMP, "unable to map BZ2_bzBuffToBuffDecompress: %s", error);
		err = -1;
		goto out;
	}
out:
	if (err) {
		errno = EINVAL;
	}
	return err;
}

int bzip2_load_lib(
	knet_handle_t knet_h)
{
	int err = 0, savederrno = 0;

	if (!bzip2_lib) {
		bzip2_lib = open_lib(knet_h, "libbz2.so.1", 0);
		if (!bzip2_lib) {
			savederrno = errno;
			err = -1;
			goto out;
		}

		if (bzip2_remap_symbols(knet_h) < 0) {
			savederrno = errno;
			err = -1;
			dlclose(bzip2_lib);
			bzip2_lib = NULL;
			goto out;
		}
	}
out:
	errno = savederrno;
	return err;
}

void bzip2_unload_lib(
	knet_handle_t knet_h)
{
	if (bzip2_lib) {
		dlclose(bzip2_lib);
		bzip2_lib = NULL;
	}
	return;
}

int bzip2_val_level(
	knet_handle_t knet_h,
	int compress_level)
{
	if ((compress_level < 1) || (compress_level > 9)) {
                log_err(knet_h, KNET_SUB_BZIP2COMP, "bzip2 unsupported compression level %d (accepted values from 1 to 9)", compress_level);
		errno = EINVAL;
		return -1;
	}
	return 0;
}

int bzip2_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int err = 0;
	int savederrno = 0;
	unsigned int destLen = KNET_DATABUFSIZE_COMPRESS;

	err = (*_int_BZ2_bzBuffToBuffCompress)((char *)buf_out, &destLen,
					       (char *)buf_in, buf_in_len,
					       knet_h->compress_level,
					       0, 0);

	switch(err) {
		case BZ_OK:
			*buf_out_len = destLen;
			break;
		case BZ_MEM_ERROR:
			log_err(knet_h, KNET_SUB_BZIP2COMP, "bzip2 compress has not enough memory");
			savederrno = ENOMEM;
			err = -1;
			break;
		case BZ_OUTBUFF_FULL:
			log_err(knet_h, KNET_SUB_BZIP2COMP, "bzip2 unable to compress source in destination buffer");
			savederrno = E2BIG;
			err = -1;
			break;
		default:
			log_err(knet_h, KNET_SUB_BZIP2COMP, "bzip2 compress unknown error %d", err);
			savederrno = EINVAL;
			err = -1;
			break;
	}

	errno = savederrno;
	return err;
}

int bzip2_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int err = 0;
	int savederrno = 0;
	unsigned int destLen = KNET_DATABUFSIZE_COMPRESS;

	err = (*_int_BZ2_bzBuffToBuffDecompress)((char *)buf_out, &destLen,
						 (char *)buf_in, buf_in_len,
						 0, 0);

	switch(err) {
		case BZ_OK:
			*buf_out_len = destLen;
			break;
		case BZ_MEM_ERROR:
			log_err(knet_h, KNET_SUB_BZIP2COMP, "bzip2 decompress has not enough memory");
			savederrno = ENOMEM;
			err = -1;
			break;
		case BZ_OUTBUFF_FULL:
			log_err(knet_h, KNET_SUB_BZIP2COMP, "bzip2 unable to decompress source in destination buffer");
			savederrno = E2BIG;
			err = -1;
			break;
		case BZ_DATA_ERROR:
		case BZ_DATA_ERROR_MAGIC:
		case BZ_UNEXPECTED_EOF:
			log_err(knet_h, KNET_SUB_BZIP2COMP, "bzip2 decompress detected input data corruption");
			savederrno = EINVAL;
			err = -1;
			break;
		default:
			log_err(knet_h, KNET_SUB_BZIP2COMP, "bzip2 decompress unknown error %d", err);
			savederrno = EINVAL;
			err = -1;
			break;
	}

	errno = savederrno;
	return err;
}
#endif
