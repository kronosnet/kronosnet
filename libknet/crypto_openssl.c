/*
 * Copyright (C) 2017-2023 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under LGPL-2.0+
 */
#define KNET_MODULE

#include "config.h"

#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
#include <openssl/hmac.h>
#endif
#include <openssl/rand.h>
#include <openssl/err.h>

#include "logging.h"
#include "crypto_model.h"

/*
 * 1.0.2 requires at least 120 bytes
 * 1.1.0 requires at least 256 bytes
 */
#define SSLERR_BUF_SIZE 512

/*
 * crypto definitions and conversion tables
 */

#define SALT_SIZE 16

/*
 * required by OSSL_PARAM_construct_*
 * making them global and cost, saves 2 strncpy and some memory on each config
 */
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
static const char *hash = "digest";
#endif

struct opensslcrypto_instance {
	void *private_key;

	int private_key_len;

	const EVP_CIPHER *crypto_cipher_type;

	const EVP_MD *crypto_hash_type;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	EVP_MAC *crypto_hash_mac;
	OSSL_PARAM params[3];
	char hash_type[16]; /* Need to store a copy from knet_handle_crypto_cfg for OSSL_PARAM_construct_* */
#endif
};

static int openssl_is_init = 0;

/*
 * crypt/decrypt functions openssl1.0
 */

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static int encrypt_openssl(
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const struct iovec *iov,
	int iovcnt,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct opensslcrypto_instance *instance = crypto_instance->model_instance;
	EVP_CIPHER_CTX	ctx;
	int		tmplen = 0, offset = 0;
	unsigned char	*salt = buf_out;
	unsigned char	*data = buf_out + SALT_SIZE;
	int		err = 0;
	int		i;
	char		sslerr[SSLERR_BUF_SIZE];

	EVP_CIPHER_CTX_init(&ctx);

	if (!RAND_bytes(salt, SALT_SIZE)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to get random salt data: %s", sslerr);
		err = -1;
		goto out;
	}

	/*
	 * add warning re keylength
	 */
	EVP_EncryptInit_ex(&ctx, instance->crypto_cipher_type, NULL, instance->private_key, salt);

	for (i=0; i<iovcnt; i++) {
		if (!EVP_EncryptUpdate(&ctx,
				       data + offset, &tmplen,
				       (unsigned char *)iov[i].iov_base, iov[i].iov_len)) {
			ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to encrypt: %s", sslerr);
			err = -1;
			goto out;
		}
		offset = offset + tmplen;
	}

	if (!EVP_EncryptFinal_ex(&ctx, data + offset, &tmplen)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to finalize encrypt: %s", sslerr);
		err = -1;
		goto out;
	}

	*buf_out_len = offset + tmplen + SALT_SIZE;

out:
	EVP_CIPHER_CTX_cleanup(&ctx);
	return err;
}

static int decrypt_openssl (
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len,
	uint8_t log_level)
{
	struct opensslcrypto_instance *instance = crypto_instance->model_instance;
	EVP_CIPHER_CTX	ctx;
	int		tmplen1 = 0, tmplen2 = 0;
	unsigned char	*salt = (unsigned char *)buf_in;
	unsigned char	*data = salt + SALT_SIZE;
	int		datalen = buf_in_len - SALT_SIZE;
	int		err = 0;
	char		sslerr[SSLERR_BUF_SIZE];

	EVP_CIPHER_CTX_init(&ctx);

	/*
	 * add warning re keylength
	 */
	EVP_DecryptInit_ex(&ctx, instance->crypto_cipher_type, NULL, instance->private_key, salt);

	if (!EVP_DecryptUpdate(&ctx, buf_out, &tmplen1, data, datalen)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		if (log_level == KNET_LOG_DEBUG) {
			log_debug(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to decrypt: %s", sslerr);
		} else {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to decrypt: %s", sslerr);
		}
		err = -1;
		goto out;
	}

	if (!EVP_DecryptFinal_ex(&ctx, buf_out + tmplen1, &tmplen2)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		if (log_level == KNET_LOG_DEBUG) {
			log_debug(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to finalize decrypt: %s", sslerr);
		} else {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to finalize decrypt: %s", sslerr);
		}
		err = -1;
		goto out;
	}

	*buf_out_len = tmplen1 + tmplen2;

out:
	EVP_CIPHER_CTX_cleanup(&ctx);
	return err;
}
#else /* (OPENSSL_VERSION_NUMBER < 0x10100000L) */
static int encrypt_openssl(
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const struct iovec *iov,
	int iovcnt,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct opensslcrypto_instance *instance = crypto_instance->model_instance;
	EVP_CIPHER_CTX	*ctx;
	int		tmplen = 0, offset = 0;
	unsigned char	*salt = buf_out;
	unsigned char	*data = buf_out + SALT_SIZE;
	int		err = 0;
	int		i;
	char		sslerr[SSLERR_BUF_SIZE];

	ctx = EVP_CIPHER_CTX_new();

	if (!RAND_bytes(salt, SALT_SIZE)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to get random salt data: %s", sslerr);
		err = -1;
		goto out;
	}

	/*
	 * add warning re keylength
	 */
	EVP_EncryptInit_ex(ctx, instance->crypto_cipher_type, NULL, instance->private_key, salt);

	for (i=0; i<iovcnt; i++) {
		if (!EVP_EncryptUpdate(ctx,
				       data + offset, &tmplen,
				       (unsigned char *)iov[i].iov_base, iov[i].iov_len)) {
			ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to encrypt: %s", sslerr);
			err = -1;
			goto out;
		}
		offset = offset + tmplen;
	}

	if (!EVP_EncryptFinal_ex(ctx, data + offset, &tmplen)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to finalize encrypt: %s", sslerr);
		err = -1;
		goto out;
	}

	*buf_out_len = offset + tmplen + SALT_SIZE;

out:
	EVP_CIPHER_CTX_free(ctx);
	return err;
}

static int decrypt_openssl (
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len,
	uint8_t log_level)
{
	struct opensslcrypto_instance *instance = crypto_instance->model_instance;
	EVP_CIPHER_CTX	*ctx = NULL;
	int		tmplen1 = 0, tmplen2 = 0;
	unsigned char	*salt = (unsigned char *)buf_in;
	unsigned char	*data = salt + SALT_SIZE;
	int		datalen = buf_in_len - SALT_SIZE;
	int		err = 0;
	char		sslerr[SSLERR_BUF_SIZE];

	if (datalen <= 0) {
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Packet is too short");
		err = -1;
		goto out;
	}

	ctx = EVP_CIPHER_CTX_new();

	/*
	 * add warning re keylength
	 */
	EVP_DecryptInit_ex(ctx, instance->crypto_cipher_type, NULL, instance->private_key, salt);

	if (!EVP_DecryptUpdate(ctx, buf_out, &tmplen1, data, datalen)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		if (log_level == KNET_LOG_DEBUG) {
			log_debug(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to decrypt: %s", sslerr);
		} else {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to decrypt: %s", sslerr);
		}
		err = -1;
		goto out;
	}

	if (!EVP_DecryptFinal_ex(ctx, buf_out + tmplen1, &tmplen2)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		if (log_level == KNET_LOG_DEBUG) {
			log_debug(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to finalize decrypt: %s", sslerr);
		} else {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to finalize decrypt: %s", sslerr);
		}
		err = -1;
		goto out;
	}

	*buf_out_len = tmplen1 + tmplen2;

out:
	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
	}
	return err;
}
#endif

/*
 * hash/hmac/digest functions
 */

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
static int calculate_openssl_hash(
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const unsigned char *buf,
	const size_t buf_len,
	unsigned char *hash,
	uint8_t log_level)
{
	struct opensslcrypto_instance *instance = crypto_instance->model_instance;
	unsigned int hash_len = 0;
	unsigned char *hash_out = NULL;
	char sslerr[SSLERR_BUF_SIZE];

	hash_out = HMAC(instance->crypto_hash_type,
			instance->private_key, instance->private_key_len,
			buf, buf_len,
			hash, &hash_len);

	if ((!hash_out) || (hash_len != crypto_instance->sec_hash_size)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		if (log_level == KNET_LOG_DEBUG) {
			log_debug(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to calculate hash: %s", sslerr);
		} else {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to calculate hash: %s", sslerr);
		}
		return -1;
	}

	return 0;
}
#else
static int calculate_openssl_hash(
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const unsigned char *buf,
	const size_t buf_len,
	unsigned char *hash,
	uint8_t log_level)
{
	struct opensslcrypto_instance *instance = crypto_instance->model_instance;
	EVP_MAC_CTX *ctx = NULL;
	char sslerr[SSLERR_BUF_SIZE];
	int err = 0;
	size_t outlen = 0;

	ctx = EVP_MAC_CTX_new(instance->crypto_hash_mac);
	if (!ctx) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to allocate openssl context: %s", sslerr);
		err = -1;
		goto out_err;
	}

	if (!EVP_MAC_init(ctx, instance->private_key, instance->private_key_len, instance->params)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to set openssl context parameters: %s", sslerr);
		err = -1;
		goto out_err;
	}

	if (!EVP_MAC_update(ctx, buf, buf_len)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to update hash: %s", sslerr);
		err = -1;
		goto out_err;
	}

	if (!EVP_MAC_final(ctx, hash, &outlen, crypto_instance->sec_hash_size)) {
		ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to finalize hash: %s", sslerr);
		err = -1;
		goto out_err;
	}

out_err:
	if (ctx) {
		EVP_MAC_CTX_free(ctx);
	}

	return err;

}
#endif

/*
 * exported API
 */

static int opensslcrypto_encrypt_and_signv (
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const struct iovec *iov_in,
	int iovcnt_in,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct opensslcrypto_instance *instance = crypto_instance->model_instance;
	int i;

	if (instance->crypto_cipher_type) {
		if (encrypt_openssl(knet_h, crypto_instance, iov_in, iovcnt_in, buf_out, buf_out_len) < 0) {
			return -1;
		}
	} else {
		*buf_out_len = 0;
		for (i=0; i<iovcnt_in; i++) {
			memmove(buf_out + *buf_out_len, iov_in[i].iov_base, iov_in[i].iov_len);
			*buf_out_len = *buf_out_len + iov_in[i].iov_len;
		}
	}

	if (instance->crypto_hash_type) {
		if (calculate_openssl_hash(knet_h, crypto_instance, buf_out, *buf_out_len, buf_out + *buf_out_len, KNET_LOG_ERR) < 0) {
			return -1;
		}
		*buf_out_len = *buf_out_len + crypto_instance->sec_hash_size;
	}

	return 0;
}

static int opensslcrypto_encrypt_and_sign (
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct iovec iov_in;

	memset(&iov_in, 0, sizeof(iov_in));
	iov_in.iov_base = (unsigned char *)buf_in;
	iov_in.iov_len = buf_in_len;

	return opensslcrypto_encrypt_and_signv(knet_h, crypto_instance, &iov_in, 1, buf_out, buf_out_len);
}

static int opensslcrypto_authenticate_and_decrypt (
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len,
	uint8_t log_level)
{
	struct opensslcrypto_instance *instance = crypto_instance->model_instance;
	ssize_t temp_len = buf_in_len;

	if (instance->crypto_hash_type) {
		unsigned char tmp_hash[crypto_instance->sec_hash_size];
		ssize_t temp_buf_len = buf_in_len - crypto_instance->sec_hash_size;

		memset(tmp_hash, 0, sizeof(tmp_hash));

		if ((temp_buf_len <= 0) || (temp_buf_len > KNET_MAX_PACKET_SIZE)) {
			log_debug(knet_h, KNET_SUB_OPENSSLCRYPTO, "Received incorrect packet size: %zu for hash size: %zu", buf_in_len, crypto_instance->sec_hash_size);
			return -1;
		}

		if (calculate_openssl_hash(knet_h, crypto_instance, buf_in, temp_buf_len, tmp_hash, log_level) < 0) {
			return -1;
		}

		if (memcmp(tmp_hash, buf_in + temp_buf_len, crypto_instance->sec_hash_size) != 0) {
			if (log_level == KNET_LOG_DEBUG) {
				log_debug(knet_h, KNET_SUB_OPENSSLCRYPTO, "Digest does not match. Check crypto key and configuration.");
			} else {
				log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Digest does not match. Check crypto key and configuration.");
			}
			return -1;
		}

		temp_len = temp_len - crypto_instance->sec_hash_size;
		*buf_out_len = temp_len;
	}
	if (instance->crypto_cipher_type) {
		if (decrypt_openssl(knet_h, crypto_instance, buf_in, temp_len, buf_out, buf_out_len, log_level) < 0) {
			return -1;
		}
	} else {
		memmove(buf_out, buf_in, temp_len);
		*buf_out_len = temp_len;
	}

	return 0;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static pthread_mutex_t *openssl_internal_lock;

static void openssl_internal_locking_callback(int mode, int type, char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		(void)pthread_mutex_lock(&(openssl_internal_lock[type]));
	} else {
		pthread_mutex_unlock(&(openssl_internal_lock[type]));
	}
}

static pthread_t openssl_internal_thread_id(void)
{
	return pthread_self();
}

static void openssl_internal_lock_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_id_callback(NULL);

	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(openssl_internal_lock[i]));
	}

	if (openssl_internal_lock) {
		free(openssl_internal_lock);
	}

	return;
}

static void openssl_atexit_handler(void)
{
	openssl_internal_lock_cleanup();
}

static int openssl_internal_lock_setup(void)
{
	int savederrno = 0, err = 0;
	int i;

	openssl_internal_lock = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (!openssl_internal_lock) {
		savederrno = errno;
		err = -1;
		goto out;
	}

	for (i = 0; i < CRYPTO_num_locks(); i++) {
		savederrno = pthread_mutex_init(&(openssl_internal_lock[i]), NULL);
		if (savederrno) {
			err = -1;
			goto out;
		}
	}

	CRYPTO_set_id_callback((void *)openssl_internal_thread_id);
	CRYPTO_set_locking_callback((void *)&openssl_internal_locking_callback);

	if (atexit(openssl_atexit_handler)) {
		err = -1;
	}
out:
	if (err) {
		openssl_internal_lock_cleanup();
	}
	errno = savederrno;
	return err;
}
#endif

static void opensslcrypto_fini(
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance)
{
	struct opensslcrypto_instance *opensslcrypto_instance = crypto_instance->model_instance;

	if (opensslcrypto_instance) {
		if (opensslcrypto_instance->private_key) {
			free(opensslcrypto_instance->private_key);
			opensslcrypto_instance->private_key = NULL;
		}
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
		if (opensslcrypto_instance->crypto_hash_mac) {
			EVP_MAC_free(opensslcrypto_instance->crypto_hash_mac);
		}
#endif
		free(opensslcrypto_instance);
		crypto_instance->model_instance = NULL;
	}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	ERR_free_strings();
#endif

	return;
}

static int opensslcrypto_init(
	knet_handle_t knet_h,
	struct crypto_instance *crypto_instance,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	struct opensslcrypto_instance *opensslcrypto_instance = NULL;
	int savederrno;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	char sslerr[SSLERR_BUF_SIZE];
	size_t params_n = 0;
#endif

	log_debug(knet_h, KNET_SUB_OPENSSLCRYPTO,
		  "Initializing openssl crypto module [%s/%s]",
		  knet_handle_crypto_cfg->crypto_cipher_type,
		  knet_handle_crypto_cfg->crypto_hash_type);

	if (!openssl_is_init) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		ERR_load_crypto_strings();
		OPENSSL_add_all_algorithms_noconf();
		if (openssl_internal_lock_setup() < 0) {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to init openssl");
			errno = EAGAIN;
			return -1;
		}
#else
		if (!OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
					 | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)) {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to init openssl");
			errno = EAGAIN;
			return -1;
		}
#endif
		openssl_is_init = 1;
	}

	crypto_instance->model_instance = malloc(sizeof(struct opensslcrypto_instance));
	if (!crypto_instance->model_instance) {
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to allocate memory for openssl model instance");
		errno = ENOMEM;
		return -1;
	}

	opensslcrypto_instance = crypto_instance->model_instance;

	memset(opensslcrypto_instance, 0, sizeof(struct opensslcrypto_instance));

	opensslcrypto_instance->private_key = malloc(knet_handle_crypto_cfg->private_key_len);
	if (!opensslcrypto_instance->private_key) {
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to allocate memory for openssl private key");
		savederrno = ENOMEM;
		goto out_err;
	}
	memmove(opensslcrypto_instance->private_key, knet_handle_crypto_cfg->private_key, knet_handle_crypto_cfg->private_key_len);
	opensslcrypto_instance->private_key_len = knet_handle_crypto_cfg->private_key_len;

	if (strcmp(knet_handle_crypto_cfg->crypto_cipher_type, "none") == 0) {
		opensslcrypto_instance->crypto_cipher_type = NULL;
	} else {
		opensslcrypto_instance->crypto_cipher_type = EVP_get_cipherbyname(knet_handle_crypto_cfg->crypto_cipher_type);
		if (!opensslcrypto_instance->crypto_cipher_type) {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unknown crypto cipher type requested");
			savederrno = ENXIO;
			goto out_err;
		}
	}

	if (strcmp(knet_handle_crypto_cfg->crypto_hash_type, "none") == 0) {
		opensslcrypto_instance->crypto_hash_type = NULL;
	} else {
		opensslcrypto_instance->crypto_hash_type = EVP_get_digestbyname(knet_handle_crypto_cfg->crypto_hash_type);
		if (!opensslcrypto_instance->crypto_hash_type) {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unknown crypto hash type requested");
			savederrno = ENXIO;
			goto out_err;
		}

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
		opensslcrypto_instance->crypto_hash_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
		if (!opensslcrypto_instance->crypto_hash_mac) {
			ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to fetch HMAC: %s", sslerr);
			savederrno = ENXIO;
			goto out_err;
		}

		/*
		 * OSSL_PARAM_construct_* store pointers to the data, it´s important that the referenced data are per-instance
		 */
		memmove(opensslcrypto_instance->hash_type, knet_handle_crypto_cfg->crypto_hash_type, sizeof(opensslcrypto_instance->hash_type));

		opensslcrypto_instance->params[params_n++] = OSSL_PARAM_construct_utf8_string(hash, opensslcrypto_instance->hash_type, 0);
		opensslcrypto_instance->params[params_n] = OSSL_PARAM_construct_end();
#endif
	}

	if ((opensslcrypto_instance->crypto_cipher_type) &&
	    (!opensslcrypto_instance->crypto_hash_type)) {
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "crypto communication requires hash specified");
		savederrno = EINVAL;
		goto out_err;
	}

	if (opensslcrypto_instance->crypto_hash_type) {
		crypto_instance->sec_hash_size = EVP_MD_size(opensslcrypto_instance->crypto_hash_type);
	}

	if (opensslcrypto_instance->crypto_cipher_type) {
		size_t block_size;

		block_size = EVP_CIPHER_block_size(opensslcrypto_instance->crypto_cipher_type);

		crypto_instance->sec_salt_size = SALT_SIZE;
		crypto_instance->sec_block_size = block_size;
	}

	return 0;

out_err:
	opensslcrypto_fini(knet_h, crypto_instance);

	errno = savederrno;
	return -1;
}

crypto_ops_t crypto_model = {
	KNET_CRYPTO_MODEL_ABI,
	opensslcrypto_init,
	opensslcrypto_fini,
	opensslcrypto_encrypt_and_sign,
	opensslcrypto_encrypt_and_signv,
	opensslcrypto_authenticate_and_decrypt
};
