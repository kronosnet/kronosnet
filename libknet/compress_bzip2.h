/*
 * Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNET_COMPRESS_BZIP2_H__
#define __KNET_COMPRESS_BZIP2_H__

#include "internals.h"

int bzip2_load_lib(
	knet_handle_t knet_h);

void bzip2_unload_lib(
	knet_handle_t knet_h);

int bzip2_val_level(
	knet_handle_t knet_h,
	int compress_level);

int bzip2_compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

int bzip2_decompress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

#endif
