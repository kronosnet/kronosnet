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
#ifdef BUILDCOMPLZO2
#include <lzo/lzo1x.h>

#include "internals.h"
#include "compress_lzo2.h"
#include "logging.h"
#include "common.h"

#define LIBLZO2_2 "liblzo2.so.2"

/*
 * global vars for dlopen
 */
static void *lzo2_lib;

/*
 * symbols remapping
 */
int (*_int_lzo1x_decompress)(const lzo_bytep src, lzo_uint src_len,
			     lzo_bytep dst, lzo_uintp dst_len,
			     lzo_voidp wrkmem /* NOT USED */ );
int (*_int_lzo1x_1_compress)(const lzo_bytep src, lzo_uint src_len,
			     lzo_bytep dst, lzo_uintp dst_len,
			     lzo_voidp wrkmem);
int (*_int_lzo1x_1_11_compress)(const lzo_bytep src, lzo_uint src_len,
				lzo_bytep dst, lzo_uintp dst_len,
				lzo_voidp wrkmem);
int (*_int_lzo1x_1_12_compress)(const lzo_bytep src, lzo_uint src_len,
				lzo_bytep dst, lzo_uintp dst_len,
				lzo_voidp wrkmem);
int (*_int_lzo1x_1_15_compress)(const lzo_bytep src, lzo_uint src_len,
				lzo_bytep dst, lzo_uintp dst_len,
				lzo_voidp wrkmem);

int (*_int_lzo1x_999_compress)(const lzo_bytep src, lzo_uint src_len,
			       lzo_bytep dst, lzo_uintp dst_len,
			       lzo_voidp wrkmem);

static int lzo2_remap_symbols(knet_handle_t knet_h)
{
	int err = 0;
	char *error = NULL;

	_int_lzo1x_decompress = dlsym(lzo2_lib, "lzo1x_decompress");
	if (!_int_lzo1x_decompress) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_LZO2COMP, "unable to map lzo1x_decompress: %s", error);
		err = -1;
		goto out;
	}

	_int_lzo1x_1_compress = dlsym(lzo2_lib, "lzo1x_1_compress");
	if (!_int_lzo1x_1_compress) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_LZO2COMP, "unable to map lzo1x_1_compress: %s", error);
		err = -1;
		goto out;
	}

	_int_lzo1x_1_11_compress = dlsym(lzo2_lib, "lzo1x_1_11_compress");
	if (!_int_lzo1x_1_11_compress) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_LZO2COMP, "unable to map lzo1x_1_11_compress: %s", error);
		err = -1;
		goto out;
	}

	_int_lzo1x_1_12_compress = dlsym(lzo2_lib, "lzo1x_1_12_compress");
	if (!_int_lzo1x_1_12_compress) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_LZO2COMP, "unable to map lzo1x_1_12_compress: %s", error);
		err = -1;
		goto out;
	}

	_int_lzo1x_1_15_compress = dlsym(lzo2_lib, "lzo1x_1_15_compress");
	if (!_int_lzo1x_1_15_compress) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_LZO2COMP, "unable to map lzo1x_1_15_compress: %s", error);
		err = -1;
		goto out;
	}

	_int_lzo1x_999_compress = dlsym(lzo2_lib, "lzo1x_999_compress");
	if (!_int_lzo1x_999_compress) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_LZO2COMP, "unable to map lzo1x_999_compress: %s", error);
		err = -1;
		goto out;
	}

out:
	if (err) {
		_int_lzo1x_decompress = NULL;
		_int_lzo1x_1_compress = NULL;
		_int_lzo1x_1_11_compress = NULL;
		_int_lzo1x_1_12_compress = NULL;
		_int_lzo1x_1_15_compress = NULL;
		_int_lzo1x_999_compress = NULL;
		errno = EINVAL;
	}
	return err;
}

int lzo2_load_lib(
	knet_handle_t knet_h)
{
	int err = 0, savederrno = 0;

	if (!lzo2_lib) {
		lzo2_lib = open_lib(knet_h, LIBLZO2_2, 0);
		if (!lzo2_lib) {
			savederrno = EAGAIN;
			err = -1;
			goto out;
		}
	}

	if (lzo2_remap_symbols(knet_h) < 0) {
		savederrno = errno;
		err = -1;
	}
out:
	errno = savederrno;
	return err;
}

int lzo2_is_init(
	knet_handle_t knet_h,
	int method_idx)
{
	if (knet_h->compress_int_data[method_idx]) {
		return 1;
	}
	return 0;
}

int lzo2_init(
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

void lzo2_fini(
	knet_handle_t knet_h,
	int method_idx)
{
	if (knet_h->compress_int_data[method_idx]) {
		free(knet_h->compress_int_data[method_idx]);
		knet_h->compress_int_data[method_idx] = NULL;
	}
	return;
}

int lzo2_val_level(
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

int lzo2_compress(
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
			lzerr = (*_int_lzo1x_1_compress)(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
			break;
		case 11:
			lzerr = (*_int_lzo1x_1_11_compress)(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
			break;
		case 12:
			lzerr = (*_int_lzo1x_1_12_compress)(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
			break;
		case 15:
			lzerr = (*_int_lzo1x_1_15_compress)(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
			break;
		case 999:
			lzerr = (*_int_lzo1x_999_compress)(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
			break;
		default:
			lzerr = (*_int_lzo1x_1_compress)(buf_in, buf_in_len, buf_out, &cmp_len, knet_h->compress_int_data[knet_h->compress_model]);
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

int lzo2_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	int lzerr = 0, err = 0;
	int savederrno = 0;
	lzo_uint decmp_len;

	lzerr = (*_int_lzo1x_decompress)(buf_in, buf_in_len, buf_out, &decmp_len, NULL);

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
#endif
