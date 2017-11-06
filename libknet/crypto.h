/*
 * Copyright (C) 2012-2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNET_CRYPTO_H__
#define __KNET_CRYPTO_H__

#include "internals.h"

struct crypto_instance {
	int	model;
	void	*model_instance;
};

typedef struct {
	const char	*model_name;
	uint8_t		built_in;

	/*
	 * see compress.h for explanation of the various lib related functions
	 */
	int (*load_lib)	(knet_handle_t knet_h);
	uint8_t		loaded;

	int (*init)	(knet_handle_t knet_h,
			 struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);
	void (*fini)	(knet_handle_t knet_h);
	int (*crypt)	(knet_handle_t knet_h,
			 const unsigned char *buf_in,
			 const ssize_t buf_in_len,
			 unsigned char *buf_out,
			 ssize_t *buf_out_len);
	int (*cryptv)	(knet_handle_t knet_h,
			 const struct iovec *iov_in,
			 int iovcnt_in,
			 unsigned char *buf_out,
			 ssize_t *buf_out_len);
	int (*decrypt)	(knet_handle_t knet_h,
			 const unsigned char *buf_in,
			 const ssize_t buf_in_len,
			 unsigned char *buf_out,
			 ssize_t *buf_out_len);
} crypto_model_t;

int crypto_authenticate_and_decrypt (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

int crypto_encrypt_and_sign (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

int crypto_encrypt_and_signv (
	knet_handle_t knet_h,
	const struct iovec *iov_in,
	int iovcnt_in,
	unsigned char *buf_out,
	ssize_t *buf_out_len);

int crypto_init(
	knet_handle_t knet_h,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);

void crypto_fini(
	knet_handle_t knet_h);

#endif
