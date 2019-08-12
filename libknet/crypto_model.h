/*
 * Copyright (C) 2012-2019 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */

#ifndef __KNET_CRYPTO_MODEL_H__
#define __KNET_CRYPTO_MODEL_H__

#include "internals.h"

struct crypto_instance {
	int	model;
	void	*model_instance;
	size_t	sec_block_size;
	size_t	sec_hash_size;
	size_t	sec_salt_size;
};

#define KNET_CRYPTO_MODEL_ABI 3

/*
 * see compress_model.h for explanation of the various lib related functions
 */
typedef struct {
	uint8_t abi_ver;
	int (*init)	(knet_handle_t knet_h,
			 struct crypto_instance *crypto_instance,
			 struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);
	void (*fini)	(knet_handle_t knet_h,
			 struct crypto_instance *crypto_instance);
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
} crypto_ops_t;

typedef struct {
	const char	*model_name;
	uint8_t		built_in;
	uint8_t		loaded;
	crypto_ops_t	*ops;
} crypto_model_t;

#endif
