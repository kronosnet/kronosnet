/*
 * Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNET_COMPRESS_H__
#define __KNET_COMPRESS_H__

#include "internals.h"

typedef struct {
	const char	*model_name;
	int (*init)     (knet_handle_t knet_h, int method_idx);
	void (*fini)    (knet_handle_t knet_h, int method_idx);
	int (*val_level)(knet_handle_t knet_h,
			 int compress_level);
	int (*compress)	(knet_handle_t knet_h,
			 const unsigned char *buf_in,
			 const ssize_t buf_in_len,
			 unsigned char *buf_out,
			 ssize_t *buf_out_len);
	int (*decompress)(knet_handle_t knet_h,
			 const unsigned char *buf_in,
			 const ssize_t buf_in_len,
			 unsigned char *buf_out,
			 ssize_t *buf_out_len);
} compress_model_t;

int compress_init(
	knet_handle_t knet_h,
	struct knet_handle_compress_cfg *knet_handle_compress_cfg);

void compress_fini(
	knet_handle_t knet_h);

int compress(
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

int decompress(
	knet_handle_t knet_h,
	int compress_model,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

/*
 * used exclusively by the test suite (see api_knet_send_compress)
 */
const char *get_model_by_idx(int idx);

#endif
