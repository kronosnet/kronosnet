/*
 * Copyright (C) 2019-2025 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */
#define KNET_MODULE

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

#include "logging.h"
#include "compress_model.h"

#ifdef ZSTD_CLEVEL_DEFAULT
#define KNET_COMPRESS_DEFAULT ZSTD_CLEVEL_DEFAULT /* zstd default compression level from zstd.h */
#else
#define KNET_COMPRESS_DEFAULT KNET_COMPRESS_UNKNOWN_DEFAULT
#endif

struct zstd_ctx {
	ZSTD_CCtx* cctx;
	ZSTD_DCtx* dctx;
};

static int zstd_is_init(
	knet_handle_t knet_h,
	int method_idx)
{
	if (knet_h->compress_int_data[method_idx]) {
		return 1;
	}
	return 0;
}

static void zstd_fini(
	knet_handle_t knet_h,
	int method_idx)
{
	struct zstd_ctx *zstd_ctx = knet_h->compress_int_data[knet_h->compress_model];

	if (zstd_ctx) {
		if (zstd_ctx->cctx) {
			ZSTD_freeCCtx(zstd_ctx->cctx);
		}
		if (zstd_ctx->dctx) {
			ZSTD_freeDCtx(zstd_ctx->dctx);
		}
		free(knet_h->compress_int_data[method_idx]);
		knet_h->compress_int_data[method_idx] = NULL;
	}
	return;
}

static int zstd_init(
	knet_handle_t knet_h,
	int method_idx)
{
	struct zstd_ctx *zstd_ctx;
	int err = 0;

	if (!knet_h->compress_int_data[method_idx]) {
		zstd_ctx = malloc(sizeof(struct zstd_ctx));
		if (!zstd_ctx) {
			errno = ENOMEM;
			return -1;
		}
		memset(zstd_ctx, 0, sizeof(struct zstd_ctx));

		knet_h->compress_int_data[method_idx] = zstd_ctx;

		zstd_ctx->cctx = ZSTD_createCCtx();
		if (!zstd_ctx->cctx) {
			log_err(knet_h, KNET_SUB_ZSTDCOMP, "Unable to create compression context");
			err = -1;
			goto out_err;
		}

		zstd_ctx->dctx = ZSTD_createDCtx();
		if (!zstd_ctx->dctx) {
			log_err(knet_h, KNET_SUB_ZSTDCOMP, "Unable to create decompression context");
			err = -1;
			goto out_err;
		}
	}

out_err:
	if (err) {
		zstd_fini(knet_h, method_idx);
	}
	return err;
}

static int zstd_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct zstd_ctx *zstd_ctx = knet_h->compress_int_data[knet_h->compress_model];
	size_t compress_size;

	compress_size = ZSTD_compressCCtx(zstd_ctx->cctx,
					  buf_out, *buf_out_len,
					  buf_in, buf_in_len,
					  knet_h->compress_level);

	if (ZSTD_isError(compress_size)) {
		log_err(knet_h, KNET_SUB_ZSTDCOMP, "error compressing packet: %s", ZSTD_getErrorName(compress_size));
		/*
		 * ZSTD has lots of internal errors that are not easy to map
		 * to standard errnos. Use a generic one for now
		 */
		errno = EINVAL;
		return -1;
	}

	*buf_out_len = compress_size;

	return 0;
}

static int zstd_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct zstd_ctx *zstd_ctx = knet_h->compress_int_data[knet_h->compress_model];
	size_t decompress_size;

	decompress_size = ZSTD_decompressDCtx(zstd_ctx->dctx,
					      buf_out, *buf_out_len,
					      buf_in, buf_in_len);

	if (ZSTD_isError(decompress_size)) {
		log_err(knet_h, KNET_SUB_ZSTDCOMP, "error decompressing packet: %s", ZSTD_getErrorName(decompress_size));
		/*
		 * ZSTD has lots of internal errors that are not easy to map
		 * to standard errnos. Use a generic one for now
		 */
		errno = EINVAL;
		return -1;
	}

	*buf_out_len = decompress_size;

	return 0;
}

static int zstd_get_default_level()
{
	return KNET_COMPRESS_DEFAULT;
}

compress_ops_t compress_model = {
	KNET_COMPRESS_MODEL_ABI,
	zstd_is_init,
	zstd_init,
	zstd_fini,
	NULL,
	zstd_compress,
	zstd_decompress,
	zstd_get_default_level
};
