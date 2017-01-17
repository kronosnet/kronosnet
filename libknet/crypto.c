/*
 * Copyright (C) 2010-2015 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "crypto.h"
#include "nsscrypto.h"
#include "internals.h"
#include "logging.h"

/*
 * internal module switch data
 */

crypto_model_t modules_cmds[] = {
	{ "nss", nsscrypto_init, nsscrypto_fini, nsscrypto_encrypt_and_sign, nsscrypto_encrypt_and_signv, nsscrypto_authenticate_and_decrypt },
	{ NULL, NULL, NULL, NULL, NULL, NULL },
};

static int get_model(const char *model)
{
	int idx = 0;

	while (modules_cmds[idx].model_name != NULL) {
		if (!strcmp(modules_cmds[idx].model_name, model))
			return idx;
		idx++;
	}
	return -1;
}

/*
 * exported API
 */

int crypto_encrypt_and_sign (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	return modules_cmds[knet_h->crypto_instance->model].crypt(knet_h, buf_in, buf_in_len, buf_out, buf_out_len);
}

int crypto_encrypt_and_signv (
	knet_handle_t knet_h,
	const struct iovec *iov_in,
	int iovcnt_in,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	return modules_cmds[knet_h->crypto_instance->model].cryptv(knet_h, iov_in, iovcnt_in, buf_out, buf_out_len);
}

int crypto_authenticate_and_decrypt (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	return modules_cmds[knet_h->crypto_instance->model].decrypt(knet_h, buf_in, buf_in_len, buf_out, buf_out_len);
}

int crypto_init(
	knet_handle_t knet_h,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	log_debug(knet_h, KNET_SUB_CRYPTO,
		  "Initizializing crypto module [%s/%s/%s]",
		  knet_handle_crypto_cfg->crypto_model,
		  knet_handle_crypto_cfg->crypto_cipher_type,
		  knet_handle_crypto_cfg->crypto_hash_type);

	knet_h->crypto_instance = malloc(sizeof(struct crypto_instance));

	if (!knet_h->crypto_instance) {
		log_err(knet_h, KNET_SUB_CRYPTO, "Unable to allocate memory for crypto instance");
		return -1;
	}

	knet_h->crypto_instance->model = get_model(knet_handle_crypto_cfg->crypto_model);
	if (knet_h->crypto_instance->model < 0) {
		log_err(knet_h, KNET_SUB_CRYPTO, "model %s not supported", knet_handle_crypto_cfg->crypto_model);
		goto out_err;
	}

	if (modules_cmds[knet_h->crypto_instance->model].init(knet_h, knet_handle_crypto_cfg))
		goto out_err;

	log_debug(knet_h, KNET_SUB_CRYPTO, "security network overhead: %u", knet_h->sec_header_size);

	return 0;

out_err:
	free(knet_h->crypto_instance);
	knet_h->crypto_instance = NULL;
	return -1;
}

void crypto_fini(
	knet_handle_t knet_h)
{
	if (knet_h->crypto_instance) {
		modules_cmds[knet_h->crypto_instance->model].fini(knet_h);
		free(knet_h->crypto_instance);
		knet_h->crypto_instance = NULL;
	}

	return;
}
