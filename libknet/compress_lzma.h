/*
 * Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNET_COMPRESS_LZMA_H__
#define __KNET_COMPRESS_LZMA_H__

#include "internals.h"

int lzma_load_lib(
	knet_handle_t knet_h);

int lzma_val_level(
	knet_handle_t knet_h,
	int compress_level);

int lzma_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

int lzma_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

#endif
