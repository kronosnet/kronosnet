/*
 * Copyright (C) 2017-2022 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */
#define KNET_MODULE
#define LZO2_COMPRESS_DEFAULT 1

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <lzo/lzo1x.h>

#include "logging.h"
#include "compress_model.h"

#ifdef LZO2_COMPRESS_DEFAULT
#define KNET_COMPRESS_DEFAULT LZO2_COMPRESS_DEFAULT
#else
#define KNET_COMPRESS_DEFAULT KNET_COMPRESS_UNKNOWN_DEFAULT
#endif

static int lzo2_is_init(
	knet_handle_t knet_h,
	int method_idx)
{
	if (knet_h->compress_int_data[method_idx]) {
		return 1;
	}
	return 0;
}

static int lzo2_init(
	knet_handle_t knet_h,
	int method_idx)
{
	/*
	 * LZO1X_999_MEM_COMPRESS is the highest amount of memory lzo2 can use
	 */
	if (!knet_h->compress_int_data[method_idx]) {
		knet_h->compress_int_data[method_idx] = malloc(LZO1X_999_MEM_COMPRESS);
		if (!knet_h->compress_int_data[method_idx]) {
			log_err(knet_h, KNET_SUB_LZO2COMP, "lzo2 unable to allocate work memory");
			errno = ENOMEM;
			return -1;
		}
		memset(knet_h->compress_int_data[method_idx], 0, LZO1X_999_MEM_COMPRESS);
	}

	return 0;
}

static void lzo2_fini(
	knet_handle_t knet_h,
	int method_idx)
{
	if (knet_h->compress_int_data[method_idx]) {
		free(knet_h->compress_int_data[method_idx]);
		knet_h->compress_int_data[method_idx] = NULL;
	}
	return;
}

static int lzo2_val_level(
	knet_handle_t knet_h,
	int compress_level)
{
	switch(compress_level) {
		case 1:
			log_debug(knet_h, KNET_SUB_LZO2COMP, "lzo2 will use lzo1x_1_compress internal compress method");
			break;
		case 11:
			log_debug(knet_h, KNET_SUB_LZO2COMP, "lzo2 will use lzo1x_1_11_compress internal compress method");
			break;
		case 12:
			log_debug(knet_h, KNET_SUB_LZO2COMP, "lzo2 will use lzo1x_1_12_compress internal compress method");
			break;
		case 15:
			log_debug(knet_h, KNET_SUB_LZO2COMP, "lzo2 will use lzo1x_1_15_compress internal compress method");
			break;
		case 999:
			log_debug(knet_h, KNET_SUB_LZO2COMP, "lzo2 will use lzo1x_999_compress internal compress method");
			break;
		default:
			log_warn(knet_h, KNET_SUB_LZO2COMP, "Unknown lzo2 internal compress method. lzo1x_1_compress will be used as default fallback");
			break;
	}

	return 0;
}

static int lzo2_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int savederrno = 0, lzerr = 0, err = 0;
	lzo_uint cmp_len;

	switch(knet_h->compress_level) {
		case 1:
			lzerr = lzo1x_1_compress(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
			break;
		case 11:
			lzerr = lzo1x_1_11_compress(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
			break;
		case 12:
			lzerr = lzo1x_1_12_compress(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
			break;
		case 15:
			lzerr = lzo1x_1_15_compress(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
			break;
		case 999:
			lzerr = lzo1x_999_compress(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
			break;
		default:
			lzerr = lzo1x_1_compress(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
			break;
	}

	if (lzerr != LZO_E_OK) {
		log_err(knet_h, KNET_SUB_LZO2COMP, "lzo2 internal compression error");
		savederrno = EAGAIN;
		err = -1;
	} else {
		*buf_out_len = cmp_len;
	}

	errno = savederrno;
	return err;
}

static int lzo2_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int lzerr = 0, err = 0;
	int savederrno = 0;
	lzo_uint decmp_len;

	lzerr = lzo1x_decompress(buf_in, buf_in_len, buf_out, &decmp_len, NULL);

	if (lzerr != LZO_E_OK) {
		log_err(knet_h, KNET_SUB_LZO2COMP, "lzo2 internal decompression error");
		savederrno = EAGAIN;
		err = -1;
	} else {
		*buf_out_len = decmp_len;
	}

	errno = savederrno;
	return err;
}

static int lzo2_get_default_level()
{
	return KNET_COMPRESS_DEFAULT;
}

compress_ops_t compress_model = {
	KNET_COMPRESS_MODEL_ABI,
	lzo2_is_init,
	lzo2_init,
	lzo2_fini,
	lzo2_val_level,
	lzo2_compress,
	lzo2_decompress,
	lzo2_get_default_level
};
