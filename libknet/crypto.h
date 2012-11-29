/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef CRYPTO_H_DEFINED
#define CRYPTO_H_DEFINED

#include <sys/types.h>
#include "libknet-private.h"

struct crypto_instance {
	int	model;
	void	*model_instance;
};

typedef struct {
	const char	*model_name;
	int (*init)	(knet_handle_t knet_h,
			 struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);
	void (*fini)	(knet_handle_t knet_h);
	int (*crypt)	(knet_handle_t knet_h,
			 const unsigned char *buf_in,
			 const ssize_t buf_in_len,
			 unsigned char *buf_out,
			 ssize_t *buf_out_len);
	int (*decrypt)	(knet_handle_t knet_h,
			 unsigned char *buf,
			 ssize_t *buf_len);
} crypto_model_t;

int crypto_authenticate_and_decrypt (
	knet_handle_t knet_h,
	unsigned char *buf,
	ssize_t *buf_len);

int crypto_encrypt_and_sign (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out, 
	ssize_t *buf_out_len);

int crypto_init(
	knet_handle_t knet_h,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);

void crypto_fini(
	knet_handle_t knet_h);

#endif /* CRYPTO_H_DEFINED */
