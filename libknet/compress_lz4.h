/*
 * Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNET_COMPRESS_LZ4_H__
#define __KNET_COMPRESS_LZ4_H__

#include "internals.h"
#include "compress_model.h"

int lz4_load_lib(
	knet_handle_t knet_h, compress_model_t *dummy);

int lz4_val_level(
	knet_handle_t knet_h,
	int compress_level);

int lz4_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

int lz4hc_val_level(
	knet_handle_t knet_h,
	int compress_level);

int lz4hc_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

int lz4_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

#endif
