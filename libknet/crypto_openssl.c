/*
 * Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#ifdef BUILDCRYPTOOPENSSL
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "common.h"
#include "crypto.h"
#include "crypto_openssl.h"
#include "logging.h"

/*
 * 1.0.2 requires at least 120 bytes
 * 1.1.0 requires at least 256 bytes
 */
#define SSLERR_BUF_SIZE 512

/*
 * make this more generic.
 * Fedora packages it one way, Debian another
 * and it changes by version
 */
#ifdef KNET_LINUX
#define LIBOPENSSL "libcrypto.so"
#endif
#ifdef KNET_BSD
#define LIBOPENSSL "libcrypto.so.10"
#endif

/*
 * global vars for dlopen
 */
static void *openssl_lib;

#include "crypto_openssl_remap.h"

static int opensslcrypto_remap_symbols(knet_handle_t knet_h)
{
#define REMAP_WITH(name) remap_symbol (knet_h, KNET_SUB_OPENSSLCRYPTO, openssl_lib, name)
#include "crypto_openssl_remap.h"
	return 0;

 fail:
#define REMAP_FAIL
#include "crypto_openssl_remap.h"
	errno = EINVAL;
	return -1;
}

static int openssl_is_init = 0;

int opensslcrypto_load_lib(
	knet_handle_t knet_h)
{
	int err = 0, savederrno = 0;

	if (!openssl_lib) {
		openssl_lib = open_lib(knet_h, LIBOPENSSL, 0);
		if (!openssl_lib) {
			savederrno = errno;
			err = -1;
			goto out;
		}
	}

	if (opensslcrypto_remap_symbols(knet_h) < 0) {
		savederrno = errno;
		err = -1;
		goto out;
	}

	if (!openssl_is_init) {
#ifdef BUILDCRYPTOOPENSSL10
		(*_int_ERR_load_crypto_strings)();
		(*_int_OPENSSL_add_all_algorithms_noconf)();
#endif
#ifdef BUILDCRYPTOOPENSSL11
		if (!(*_int_OPENSSL_init_crypto)(OPENSSL_INIT_ADD_ALL_CIPHERS \
						 | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)) {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to init openssl");
			err = -1;
			savederrno = EAGAIN;
			goto out;
		}
#endif
		openssl_is_init = 1;
	}

out:
	errno = savederrno;
	return err;
}

/*
 * crypto definitions and conversion tables
 */

#define SALT_SIZE 16

struct opensslcrypto_instance {
	void *private_key;

	int private_key_len;

	const EVP_CIPHER *crypto_cipher_type;

	const EVP_MD *crypto_hash_type;
};

/*
 * crypt/decrypt functions openssl1.0
 */

#ifdef BUILDCRYPTOOPENSSL10
static int encrypt_openssl(
	knet_handle_t knet_h,
	const struct iovec *iov,
	int iovcnt,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct opensslcrypto_instance *instance = knet_h->crypto_instance->model_instance;
	EVP_CIPHER_CTX	ctx;
	int		tmplen = 0, offset = 0;
	unsigned char	*salt = buf_out;
	unsigned char	*data = buf_out + SALT_SIZE;
	int		err = 0;
	int		i;
	char		sslerr[SSLERR_BUF_SIZE];

	(*_int_EVP_CIPHER_CTX_init)(&ctx);

	/*
	 * contribute to PRNG for each packet we send/receive
	 */
	(*_int_RAND_seed)((unsigned char *)iov[iovcnt - 1].iov_base, iov[iovcnt - 1].iov_len);

	if (!(*_int_RAND_bytes)(salt, SALT_SIZE)) {
		(*_int_ERR_error_string_n)((*_int_ERR_get_error)(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to get random salt data: %s", sslerr);
		err = -1;
		goto out;
	}

	/*
	 * add warning re keylength
	 */
	(*_int_EVP_EncryptInit_ex)(&ctx, instance->crypto_cipher_type, NULL, instance->private_key, salt);

	for (i=0; i<iovcnt; i++) {
		if (!(*_int_EVP_EncryptUpdate)(&ctx,
					       data + offset, &tmplen,
					       (unsigned char *)iov[i].iov_base, iov[i].iov_len)) {
			(*_int_ERR_error_string_n)((*_int_ERR_get_error)(), sslerr, sizeof(sslerr));
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to encrypt: %s", sslerr);
			err = -1;
			goto out;
		}
		offset = offset + tmplen;
	}

	if (!(*_int_EVP_EncryptFinal_ex)(&ctx, data + offset, &tmplen)) {
		(*_int_ERR_error_string_n)((*_int_ERR_get_error)(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to finalize encrypt: %s", sslerr);
		err = -1;
		goto out;
	}

	*buf_out_len = offset + tmplen + SALT_SIZE;

out:
	(*_int_EVP_CIPHER_CTX_cleanup)(&ctx);
	return err;
}

static int decrypt_openssl (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct opensslcrypto_instance *instance = knet_h->crypto_instance->model_instance;
	EVP_CIPHER_CTX	ctx;
	int		tmplen1 = 0, tmplen2 = 0;
	unsigned char	*salt = (unsigned char *)buf_in;
	unsigned char	*data = salt + SALT_SIZE;
	int		datalen = buf_in_len - SALT_SIZE;
	int		err = 0;
	char		sslerr[SSLERR_BUF_SIZE];

	(*_int_EVP_CIPHER_CTX_init)(&ctx);

	/*
	 * contribute to PRNG for each packet we send/receive
	 */
	(*_int_RAND_seed)(buf_in, buf_in_len);

	/*
	 * add warning re keylength
	 */
	(*_int_EVP_DecryptInit_ex)(&ctx, instance->crypto_cipher_type, NULL, instance->private_key, salt);

	if (!(*_int_EVP_DecryptUpdate)(&ctx, buf_out, &tmplen1, data, datalen)) {
		(*_int_ERR_error_string_n)((*_int_ERR_get_error)(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to decrypt: %s", sslerr);
		err = -1;
		goto out;
	}

	if (!(*_int_EVP_DecryptFinal_ex)(&ctx, buf_out + tmplen1, &tmplen2)) {
		(*_int_ERR_error_string_n)((*_int_ERR_get_error)(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to finalize decrypt: %s", sslerr);
		err = -1;
		goto out;
	}

	*buf_out_len = tmplen1 + tmplen2;

out:
	(*_int_EVP_CIPHER_CTX_cleanup)(&ctx);
	return err;
}
#endif

#ifdef BUILDCRYPTOOPENSSL11
static int encrypt_openssl(
	knet_handle_t knet_h,
	const struct iovec *iov,
	int iovcnt,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct opensslcrypto_instance *instance = knet_h->crypto_instance->model_instance;
	EVP_CIPHER_CTX	*ctx;
	int		tmplen = 0, offset = 0;
	unsigned char	*salt = buf_out;
	unsigned char	*data = buf_out + SALT_SIZE;
	int		err = 0;
	int		i;
	char		sslerr[SSLERR_BUF_SIZE];

	ctx = (*_int_EVP_CIPHER_CTX_new)();

	/*
	 * contribute to PRNG for each packet we send/receive
	 */
	(*_int_RAND_seed)((unsigned char *)iov[iovcnt - 1].iov_base, iov[iovcnt - 1].iov_len);

	if (!(*_int_RAND_bytes)(salt, SALT_SIZE)) {
		(*_int_ERR_error_string_n)((*_int_ERR_get_error)(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to get random salt data: %s", sslerr);
		err = -1;
		goto out;
	}

	/*
	 * add warning re keylength
	 */
	(*_int_EVP_EncryptInit_ex)(ctx, instance->crypto_cipher_type, NULL, instance->private_key, salt);

	for (i=0; i<iovcnt; i++) {
		if (!(*_int_EVP_EncryptUpdate)(ctx,
					       data + offset, &tmplen,
					       (unsigned char *)iov[i].iov_base, iov[i].iov_len)) {
			(*_int_ERR_error_string_n)((*_int_ERR_get_error)(), sslerr, sizeof(sslerr));
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to encrypt: %s", sslerr);
			err = -1;
			goto out;
		}
		offset = offset + tmplen;
	}

	if (!(*_int_EVP_EncryptFinal_ex)(ctx, data + offset, &tmplen)) {
		(*_int_ERR_error_string_n)((*_int_ERR_get_error)(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to finalize encrypt: %s", sslerr);
		err = -1;
		goto out;
	}

	*buf_out_len = offset + tmplen + SALT_SIZE;

out:
	(*_int_EVP_CIPHER_CTX_free)(ctx);
	return err;
}

static int decrypt_openssl (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct opensslcrypto_instance *instance = knet_h->crypto_instance->model_instance;
	EVP_CIPHER_CTX	*ctx;
	int		tmplen1 = 0, tmplen2 = 0;
	unsigned char	*salt = (unsigned char *)buf_in;
	unsigned char	*data = salt + SALT_SIZE;
	int		datalen = buf_in_len - SALT_SIZE;
	int		err = 0;
	char		sslerr[SSLERR_BUF_SIZE];

	ctx = (*_int_EVP_CIPHER_CTX_new)();

	/*
	 * contribute to PRNG for each packet we send/receive
	 */
	(*_int_RAND_seed)(buf_in, buf_in_len);

	/*
	 * add warning re keylength
	 */
	(*_int_EVP_DecryptInit_ex)(ctx, instance->crypto_cipher_type, NULL, instance->private_key, salt);

	if (!(*_int_EVP_DecryptUpdate)(ctx, buf_out, &tmplen1, data, datalen)) {
		(*_int_ERR_error_string_n)((*_int_ERR_get_error)(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to decrypt: %s", sslerr);
		err = -1;
		goto out;
	}

	if (!(*_int_EVP_DecryptFinal_ex)(ctx, buf_out + tmplen1, &tmplen2)) {
		(*_int_ERR_error_string_n)((*_int_ERR_get_error)(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to finalize decrypt: %s", sslerr);
		err = -1;
		goto out;
	}

	*buf_out_len = tmplen1 + tmplen2;

out:
	(*_int_EVP_CIPHER_CTX_free)(ctx);
	return err;
}
#endif

/*
 * hash/hmac/digest functions
 */

static int calculate_openssl_hash(
	knet_handle_t knet_h,
	const unsigned char *buf,
	const size_t buf_len,
	unsigned char *hash)
{
	struct opensslcrypto_instance *instance = knet_h->crypto_instance->model_instance;
	unsigned int hash_len = 0;
	unsigned char *hash_out = NULL;
	char sslerr[SSLERR_BUF_SIZE];

	hash_out = (*_int_HMAC)(instance->crypto_hash_type,
				instance->private_key, instance->private_key_len,
				buf, buf_len,
				hash, &hash_len);

	if ((!hash_out) || (hash_len != knet_h->sec_hash_size)) {
		(*_int_ERR_error_string_n)((*_int_ERR_get_error)(), sslerr, sizeof(sslerr));
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to calculate hash: %s", sslerr);
		return -1;
	}

	return 0;
}

/*
 * exported API
 */

int opensslcrypto_encrypt_and_sign (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct iovec iov_in;

	memset(&iov_in, 0, sizeof(iov_in));
	iov_in.iov_base = (unsigned char *)buf_in;
	iov_in.iov_len = buf_in_len;

	return opensslcrypto_encrypt_and_signv(knet_h, &iov_in, 1, buf_out, buf_out_len);
}

int opensslcrypto_encrypt_and_signv (
	knet_handle_t knet_h,
	const struct iovec *iov_in,
	int iovcnt_in,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct opensslcrypto_instance *instance = knet_h->crypto_instance->model_instance;
	int i;

	if (instance->crypto_cipher_type) {
		if (encrypt_openssl(knet_h, iov_in, iovcnt_in, buf_out, buf_out_len) < 0) {
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
		if (calculate_openssl_hash(knet_h, buf_out, *buf_out_len, buf_out + *buf_out_len) < 0) {
			return -1;
		}
		*buf_out_len = *buf_out_len + knet_h->sec_hash_size;
	}

	return 0;
}

int opensslcrypto_authenticate_and_decrypt (
	knet_handle_t knet_h,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out,
	ssize_t *buf_out_len)
{
	struct opensslcrypto_instance *instance = knet_h->crypto_instance->model_instance;
	ssize_t temp_len = buf_in_len;

	if (instance->crypto_hash_type) {
		unsigned char tmp_hash[knet_h->sec_hash_size];
		ssize_t temp_buf_len = buf_in_len - knet_h->sec_hash_size;

		if ((temp_buf_len < 0) || (temp_buf_len > KNET_MAX_PACKET_SIZE)) {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Incorrect packet size.");
			return -1;
		}

		if (calculate_openssl_hash(knet_h, buf_in, temp_buf_len, tmp_hash) < 0) {
			return -1;
		}

		if (memcmp(tmp_hash, buf_in + temp_buf_len, knet_h->sec_hash_size) != 0) {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Digest does not match");
			return -1;
		}

		temp_len = temp_len - knet_h->sec_hash_size;
		*buf_out_len = temp_len;
	}
	if (instance->crypto_cipher_type) {
		if (decrypt_openssl(knet_h, buf_in, temp_len, buf_out, buf_out_len) < 0) {
			return -1;
		}
	} else {
		memmove(buf_out, buf_in, temp_len);
		*buf_out_len = temp_len;
	}

	return 0;
}

int opensslcrypto_init(
	knet_handle_t knet_h,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg)
{
	struct opensslcrypto_instance *opensslcrypto_instance = NULL;

	log_debug(knet_h, KNET_SUB_OPENSSLCRYPTO,
		  "Initizializing openssl crypto module [%s/%s]",
		  knet_handle_crypto_cfg->crypto_cipher_type,
		  knet_handle_crypto_cfg->crypto_hash_type);

	knet_h->crypto_instance->model_instance = malloc(sizeof(struct opensslcrypto_instance));
	if (!knet_h->crypto_instance->model_instance) {
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to allocate memory for openssl model instance");
		return -1;
	}

	opensslcrypto_instance = knet_h->crypto_instance->model_instance;

	memset(opensslcrypto_instance, 0, sizeof(struct opensslcrypto_instance));

	if (strcmp(knet_handle_crypto_cfg->crypto_cipher_type, "none") == 0) {
		opensslcrypto_instance->crypto_cipher_type = NULL;
	} else {
		opensslcrypto_instance->crypto_cipher_type = (*_int_EVP_get_cipherbyname)(knet_handle_crypto_cfg->crypto_cipher_type);
		if (!opensslcrypto_instance->crypto_cipher_type) {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unknown crypto cipher type requested");
			goto out_err;
		}
	}

	if (strcmp(knet_handle_crypto_cfg->crypto_hash_type, "none") == 0) {
		opensslcrypto_instance->crypto_hash_type = NULL;
	} else {
		opensslcrypto_instance->crypto_hash_type = (*_int_EVP_get_digestbyname)(knet_handle_crypto_cfg->crypto_hash_type);
		if (!opensslcrypto_instance->crypto_hash_type) {
			log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unknown crypto hash type requested");
			goto out_err;
		}
	}

	if ((opensslcrypto_instance->crypto_cipher_type) &&
	    (!opensslcrypto_instance->crypto_hash_type)) {
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "crypto communication requires hash specified");
		goto out_err;
	}

	opensslcrypto_instance->private_key = malloc(knet_handle_crypto_cfg->private_key_len);
	if (!opensslcrypto_instance->private_key) {
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "Unable to allocate memory for openssl private key");
		goto out_err;
	}
	memmove(opensslcrypto_instance->private_key, knet_handle_crypto_cfg->private_key, knet_handle_crypto_cfg->private_key_len);
	opensslcrypto_instance->private_key_len = knet_handle_crypto_cfg->private_key_len;

	knet_h->sec_header_size = 0;

	if (opensslcrypto_instance->crypto_hash_type) {
		knet_h->sec_hash_size = (*_int_EVP_MD_size)(opensslcrypto_instance->crypto_hash_type);
		knet_h->sec_header_size += knet_h->sec_hash_size;
	}

	if (opensslcrypto_instance->crypto_cipher_type) {
		int block_size;

		block_size = (*_int_EVP_CIPHER_block_size)(opensslcrypto_instance->crypto_cipher_type);
		if (block_size < 0) {
			goto out_err;
		}

		knet_h->sec_header_size += (block_size * 2);
		knet_h->sec_header_size += SALT_SIZE;
		knet_h->sec_salt_size = SALT_SIZE;
		knet_h->sec_block_size = block_size;
	}

	return 0;

out_err:
	opensslcrypto_fini(knet_h);

	return -1;
}

void opensslcrypto_fini(
	knet_handle_t knet_h)
{
	struct opensslcrypto_instance *opensslcrypto_instance = knet_h->crypto_instance->model_instance;

	if (opensslcrypto_instance) {
		if (opensslcrypto_instance->private_key) {
			free(opensslcrypto_instance->private_key);
			opensslcrypto_instance->private_key = NULL;
		}
		free(opensslcrypto_instance);
		knet_h->crypto_instance->model_instance = NULL;
		knet_h->sec_header_size = 0;
	}

	return;
}
#endif
