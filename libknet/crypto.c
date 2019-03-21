/*
 * Copyright (C) 2012-2019 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include "crypto.h"
#include "crypto_model.h"
#include "internals.h"
#include "logging.h"
#include "common.h"

/*
 * internal module switch data
 */

static crypto_model_t crypto_modules_cmds[] = {
	{ "nss", WITH_CRYPTO_NSS, 0, NULL },
	{ "openssl", WITH_CRYPTO_OPENSSL, 0, NULL },
	{ NULL, 0, 0, NULL }
};

static int crypto_get_model(const char *model)
{
	int idx = 0;

	while (crypto_modules_cmds[idx].model_name != NULL) {
		if (!strcmp(crypto_modules_cmds[idx].model_name, model))
			return idx;
		idx++;
	}
	return -1;
}

/*
 * exported internal API
 */

int crypto_encrypt_and_sign (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	return crypto_modules_cmds[knet_h->crypto_instance->model].ops->crypt(knet_h, buf_in, buf_in_len, buf_out, buf_out_len);
}

int crypto_encrypt_and_signv (
	knet_handle_t knet_h,
	const struct iovec *iov_in,
	int iovcnt_in,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	return crypto_modules_cmds[knet_h->crypto_instance->model].ops->cryptv(knet_h, iov_in, iovcnt_in, buf_out, buf_out_len);
}

int crypto_authenticate_and_decrypt (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	return crypto_modules_cmds[knet_h->crypto_instance->model].ops->decrypt(knet_h, buf_in, buf_in_len, buf_out, buf_out_len);
}

void crypto_fini(
	knet_handle_t knet_h)
{
	int savederrno = 0;
	int model = 0;

	savederrno = pthread_rwlock_wrlock(&shlib_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_CRYPTO, "Unable to get write lock: %s",
			strerror(savederrno));
		return;
	}

	if (knet_h->crypto_instance) {
		model = knet_h->crypto_instance->model;
		if (crypto_modules_cmds[model].ops->fini != NULL) {
			crypto_modules_cmds[model].ops->fini(knet_h);
		}
		free(knet_h->crypto_instance);
		knet_h->crypto_instance = NULL;
	}

	pthread_rwlock_unlock(&shlib_rwlock);
	return;
}

/*
 * internal API
 */

static int crypto_init(
	knet_handle_t knet_h,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	int savederrno = 0;
	int model = 0;

	model = crypto_get_model(knet_handle_crypto_cfg->crypto_model);
	if (model < 0) {
		log_err(knet_h, KNET_SUB_CRYPTO, "model %s not supported", knet_handle_crypto_cfg->crypto_model);
		return -1;
	}

	if (crypto_modules_cmds[model].built_in == 0) {
		log_err(knet_h, KNET_SUB_CRYPTO, "this version of libknet was built without %s support. Please contact your vendor or fix the build.", knet_handle_crypto_cfg->crypto_model);
		return -1;
	}

	savederrno = pthread_rwlock_wrlock(&shlib_rwlock);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_CRYPTO, "Unable to get write lock: %s",
			strerror(savederrno));
		return -1;
	}

	if (!crypto_modules_cmds[model].loaded) {
		crypto_modules_cmds[model].ops = load_module (knet_h, "crypto", crypto_modules_cmds[model].model_name);
		if (!crypto_modules_cmds[model].ops) {
			savederrno = errno;
			log_err(knet_h, KNET_SUB_CRYPTO, "Unable to load %s lib", crypto_modules_cmds[model].model_name);
			goto out_err;
		}
		if (crypto_modules_cmds[model].ops->abi_ver != KNET_CRYPTO_MODEL_ABI) {
			log_err(knet_h, KNET_SUB_CRYPTO,
				"ABI mismatch loading module %s. knet ver: %d, module ver: %d",
				crypto_modules_cmds[model].model_name, KNET_CRYPTO_MODEL_ABI,
				crypto_modules_cmds[model].ops->abi_ver);
			savederrno = EINVAL;
			goto out_err;
		}
		crypto_modules_cmds[model].loaded = 1;
	}

	log_debug(knet_h, KNET_SUB_CRYPTO,
		  "Initizializing crypto module [%s/%s/%s]",
		  knet_handle_crypto_cfg->crypto_model,
		  knet_handle_crypto_cfg->crypto_cipher_type,
		  knet_handle_crypto_cfg->crypto_hash_type);

	knet_h->crypto_instance = malloc(sizeof(struct crypto_instance));

	if (!knet_h->crypto_instance) {
		log_err(knet_h, KNET_SUB_CRYPTO, "Unable to allocate memory for crypto instance");
		pthread_rwlock_unlock(&shlib_rwlock);
		savederrno = ENOMEM;
		goto out_err;
	}

	memset(knet_h->crypto_instance, 0, sizeof(struct crypto_instance));

	/*
	 * if crypto_modules_cmds.ops->init fails, it is expected that
	 * it will clean everything by itself.
	 * crypto_modules_cmds.ops->fini is not invoked on error.
	 */
	knet_h->crypto_instance->model = model;
	if (crypto_modules_cmds[knet_h->crypto_instance->model].ops->init(knet_h, knet_handle_crypto_cfg)) {
		savederrno = errno;
		goto out_err;
	}

	log_debug(knet_h, KNET_SUB_CRYPTO, "security network overhead: %zu", knet_h->sec_header_size);
	pthread_rwlock_unlock(&shlib_rwlock);
	return 0;

out_err:
	if (knet_h->crypto_instance) {
		free(knet_h->crypto_instance);
		knet_h->crypto_instance = NULL;
	}

	pthread_rwlock_unlock(&shlib_rwlock);
	errno = savederrno;
	return -1;
}

/*
 * public API
 */

int knet_get_crypto_list(struct knet_crypto_info *crypto_list, size_t *crypto_list_entries)
{
	int err = 0;
	int idx = 0;
	int outidx = 0;

	if (!crypto_list_entries) {
		errno = EINVAL;
		return -1;
	}

	while (crypto_modules_cmds[idx].model_name != NULL) {
		if (crypto_modules_cmds[idx].built_in) {
			if (crypto_list) {
				crypto_list[outidx].name = crypto_modules_cmds[idx].model_name;
			}
			outidx++;
		}
		idx++;
	}
	*crypto_list_entries = outidx;

	if (!err)
		errno = 0;
	return err;
}


int knet_handle_crypto(knet_handle_t knet_h, struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	int savederrno = 0;
	int err = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!knet_handle_crypto_cfg) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if ((!strncmp("none", knet_handle_crypto_cfg->crypto_model, 4)) ||
	    ((!strncmp("none", knet_handle_crypto_cfg->crypto_cipher_type, 4)) &&
	     (!strncmp("none", knet_handle_crypto_cfg->crypto_hash_type, 4)))) {
		knet_h->crypto_rekey_in_progress = 0;
		crypto_fini(knet_h);
		log_debug(knet_h, KNET_SUB_CRYPTO, "crypto is not enabled");
		err = 0;
		goto exit_unlock;
	}

	/*
	 * Allow to deconfigure crypto even during a rekey process
	 * to save a call to stop_rekey in case of aborting the rekey
	 * process or shutdown of the application.
	 */
	if (knet_h->crypto_rekey_in_progress) {
		savederrno = EBUSY;
		log_err(knet_h, KNET_SUB_HANDLE, "Crypto rekey in progress, cannot change crypto config: %s",
			strerror(savederrno));
		errno = savederrno;
		err = -1;
		goto exit_unlock;
	}

	/*
	 * we can only check for those parameters after
	 * checking the crypto_modes/cipher and hast type
	 * as they might have invalid values for "none".
	 */
	if (knet_handle_crypto_cfg->private_key_len < KNET_MIN_KEY_LEN) {
		log_debug(knet_h, KNET_SUB_CRYPTO, "private key len too short (min %d): %u",
			  KNET_MIN_KEY_LEN, knet_handle_crypto_cfg->private_key_len);
		savederrno = EINVAL;
		err = -1;
		goto exit_unlock;
	}

	if (knet_handle_crypto_cfg->private_key_len > KNET_MAX_KEY_LEN) {
		log_debug(knet_h, KNET_SUB_CRYPTO, "private key len too long (max %d): %u",
			  KNET_MAX_KEY_LEN, knet_handle_crypto_cfg->private_key_len);
		savederrno = EINVAL;
		err = -1;
		goto exit_unlock;
	}

	crypto_fini(knet_h);
	err = crypto_init(knet_h, knet_handle_crypto_cfg);

	if (err) {
		err = -2;
		savederrno = errno;
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_handle_crypto_start_rekey(knet_handle_t knet_h, struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	int savederrno = 0;
	int err = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	if (!knet_handle_crypto_cfg) {
		errno = EINVAL;
		return -1;
	}

	if (knet_handle_crypto_cfg->private_key_len < KNET_MIN_KEY_LEN) {
		log_debug(knet_h, KNET_SUB_CRYPTO, "private key len too short (min %d): %u",
			  KNET_MIN_KEY_LEN, knet_handle_crypto_cfg->private_key_len);
		errno = EINVAL;
		return -1;
	}

	if (knet_handle_crypto_cfg->private_key_len > KNET_MAX_KEY_LEN) {
		log_debug(knet_h, KNET_SUB_CRYPTO, "private key len too long (max %d): %u",
			  KNET_MAX_KEY_LEN, knet_handle_crypto_cfg->private_key_len);
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (knet_h->crypto_rekey_in_progress) {
		savederrno = EBUSY;
		log_err(knet_h, KNET_SUB_HANDLE, "Crypto rekey in progress, cannot change crypto config: %s",
			strerror(savederrno));
		errno = savederrno;
		err = -1;
		goto exit_unlock;
	}

	if (!knet_h->crypto_instance) {
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HANDLE, "Crypto is not configured, unable to load new keys: %s",
			strerror(savederrno));
		errno = savederrno;
		err = -1;
		goto exit_unlock;
	}

	/*
	 * crypto_start_rekey needs to make sure
	 * that both keys are loaded and that in case
	 * of failure to load the new key, all new allocated resources
	 * are cleared and freed.
	 */
	err = crypto_modules_cmds[knet_h->crypto_instance->model].ops->start_rekey(knet_h, knet_handle_crypto_cfg);
	savederrno = errno;

	if (err) {
		err = -2;
	} else {
		knet_h->crypto_rekey_in_progress = 1;
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_handle_crypto_use_newkey(knet_handle_t knet_h)
{
	int savederrno = 0;
	int err = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!knet_h->crypto_instance) {
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HANDLE, "Crypto is not configured, unable to load new keys: %s",
			strerror(savederrno));
		errno = savederrno;
		err = -1;
		goto exit_unlock;
	}

	if (!knet_h->crypto_rekey_in_progress) {
		savederrno = ENOENT;
		log_err(knet_h, KNET_SUB_HANDLE, "Crypto rekey not started: %s",
			strerror(savederrno));
		errno = savederrno;
		err = -1;
		goto exit_unlock;
	}

	knet_h->crypto_instance->active_instance = 1 - knet_h->crypto_instance->active_instance;

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}

int knet_handle_crypto_stop_rekey(knet_handle_t knet_h)
{
	int savederrno = 0;
	int err = 0;

	if (!knet_h) {
		errno = EINVAL;
		return -1;
	}

	savederrno = get_global_wrlock(knet_h);
	if (savederrno) {
		log_err(knet_h, KNET_SUB_HANDLE, "Unable to get write lock: %s",
			strerror(savederrno));
		errno = savederrno;
		return -1;
	}

	if (!knet_h->crypto_instance) {
		savederrno = EINVAL;
		log_err(knet_h, KNET_SUB_HANDLE, "Crypto is not configured, unable to load new keys: %s",
			strerror(savederrno));
		errno = savederrno;
		err = -1;
		goto exit_unlock;
	}

	if (!knet_h->crypto_rekey_in_progress) {
		savederrno = ENOENT;
		log_err(knet_h, KNET_SUB_HANDLE, "Crypto rekey not started: %s",
			strerror(savederrno));
		errno = savederrno;
		err = -1;
		goto exit_unlock;
	}

	err = crypto_modules_cmds[knet_h->crypto_instance->model].ops->stop_rekey(knet_h);
	savederrno = errno;

	if (!err) {
		knet_h->crypto_rekey_in_progress = 0;
	}

exit_unlock:
	pthread_rwlock_unlock(&knet_h->global_rwlock);
	errno = err ? savederrno : 0;
	return err;
}
