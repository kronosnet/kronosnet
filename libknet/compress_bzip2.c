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
#include <bzlib.h>

#include "logging.h"
#include "compress_model.h"

static int bzip2_val_level(
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

static int bzip2_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int err = 0;
	int savederrno = 0;
	unsigned int destLen = KNET_DATABUFSIZE_COMPRESS;

	err = BZ2_bzBuffToBuffCompress((char *)buf_out, &destLen,
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

static int bzip2_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int err = 0;
	int savederrno = 0;
	unsigned int destLen = KNET_DATABUFSIZE_COMPRESS;

	err = BZ2_bzBuffToBuffDecompress((char *)buf_out, &destLen,
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

compress_ops_t compress_model = {
	KNET_COMPRESS_MODEL_ABI,
	NULL,
	NULL,
	NULL,
	bzip2_val_level,
	bzip2_compress,
	bzip2_decompress
};
