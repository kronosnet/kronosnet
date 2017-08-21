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
#ifdef BUILDCOMPLZMA
#include <lzma.h>

#include "internals.h"
#include "compress_lzma.h"
#include "logging.h"

/*
 * global vars for dlopen
 */
static void *lzma_lib;
static int lmza_libref = 0;

/*
 * symbols remapping
 */
int (*_int_lzma_easy_buffer_encode)(
		uint32_t preset, lzma_check check,
		const lzma_allocator *allocator,
		const uint8_t *in, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size);
int (*_int_lzma_stream_buffer_decode)(
		uint64_t *memlimit, uint32_t flags,
		const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size);

static int lzma_remap_symbols(knet_handle_t knet_h)
{
	int err = 0;
	char *error = NULL;

	_int_lzma_easy_buffer_encode = dlsym(lzma_lib, "lzma_easy_buffer_encode");
	if (!_int_lzma_easy_buffer_encode) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_LZMACOMP, "unable to map lzma_easy_buffer_encode: %s", error);
		err = -1;
		goto out;
	}

	_int_lzma_stream_buffer_decode = dlsym(lzma_lib, "lzma_stream_buffer_decode");
	if (!_int_lzma_stream_buffer_decode) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_LZMACOMP, "unable to map lzma_stream_buffer_decode: %s", error);
		err = -1;
		goto out;
	}
out:
	if (err) {
		errno = EINVAL;
	}
	return err;
}

void lzma_fini(
	knet_handle_t knet_h,
	int method_idx)
{
	lmza_libref--;
	if ((lzma_lib) && (lmza_libref == 0)) {
		dlclose(lzma_lib);
		lzma_lib = NULL;
	}
	return;
}

int lzma_init(
	knet_handle_t knet_h,
	int method_idx)
{
	int err = 0, savederrno = 0;
	char *error = NULL;

	if (!lzma_lib) {
		/*
		 * clear any pending error
		 */
		dlerror();

		lzma_lib = dlopen("liblzma.so.5", RTLD_LAZY | RTLD_GLOBAL);
		error = dlerror();
		if (error != NULL) {
			log_err(knet_h, KNET_SUB_LZMACOMP, "unable to dlopen liblzma.so.5: %s", error);
			savederrno = EAGAIN;
			err = -1;
			goto out;
		}

		if (lzma_remap_symbols(knet_h) < 0) {
			savederrno = errno;
			err = -1;
			goto out;
		}
	}
	lmza_libref++;
out:
	errno = savederrno;
	return err;
}

int lzma_val_level(
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

int lzma_compress(
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

	ret = (*_int_lzma_easy_buffer_encode)(knet_h->compress_level, LZMA_CHECK_NONE, NULL,
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

int lzma_decompress(
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

	ret = (*_int_lzma_stream_buffer_decode)(&memlimit, 0, NULL,
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
#endif
