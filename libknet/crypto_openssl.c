/*
 * Copyright (C) 2010-2017 Red Hat, Inc.  All rights reserved.
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
#define LIBOPENSSL "libcrypto.so"

/*
 * global vars for dlopen
 */
static void *openssl_lib;

/*
 * symbols remapping
 */
#ifdef BUILDCRYPTOOPENSSL10
void (*_int_OPENSSL_add_all_algorithms_noconf)(void);
#endif
#ifdef BUILDCRYPTOOPENSSL11
int (*_int_OPENSSL_init_crypto)(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
#endif

#ifdef BUILDCRYPTOOPENSSL10
void (*_int_ERR_load_crypto_strings)(void);
#endif
unsigned long (*_int_ERR_get_error)(void);
void (*_int_ERR_error_string_n)(unsigned long e, char *buf, size_t len);
#ifdef BUILDCRYPTOOPENSSL10
void (*_int_ERR_free_strings)(void);
#endif

void (*_int_RAND_seed)(const void *buf, int num);
int (*_int_RAND_bytes)(unsigned char *buf, int num);

const EVP_MD *(*_int_EVP_get_digestbyname)(const char *name);
int (*_int_EVP_MD_size)(const EVP_MD *md);
unsigned char *(*_int_HMAC)(const EVP_MD *evp_md, const void *key, int key_len,
			    const unsigned char *d, size_t n, unsigned char *md,
			    unsigned int *md_len);

const EVP_CIPHER *(*_int_EVP_get_cipherbyname)(const char *name);
int (*_int_EVP_CIPHER_block_size)(const EVP_CIPHER *cipher);

#ifdef BUILDCRYPTOOPENSSL10
void (*_int_EVP_CIPHER_CTX_init)(EVP_CIPHER_CTX *a);
int (*_int_EVP_CIPHER_CTX_cleanup)(EVP_CIPHER_CTX *a);
#endif
#ifdef BUILDCRYPTOOPENSSL11
EVP_CIPHER_CTX *(*_int_EVP_CIPHER_CTX_new)(void);
void (*_int_EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *c);
#endif

int (*_int_EVP_EncryptInit_ex)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
			       ENGINE *impl, const unsigned char *key,
			       const unsigned char *iv);
int (*_int_EVP_EncryptUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
			      const unsigned char *in, int inl);
int (*_int_EVP_EncryptFinal_ex)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int (*_int_EVP_DecryptInit_ex)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
			       ENGINE *impl, const unsigned char *key,
			       const unsigned char *iv);
int (*_int_EVP_DecryptUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
			      const unsigned char *in, int inl);
int (*_int_EVP_DecryptFinal_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

#ifdef BUILDCRYPTOOPENSSL10
void (*_int_EVP_cleanup)(void);
#endif

static void clean_openssl_syms(void)
{
#ifdef BUILDCRYPTOOPENSSL10
	_int_OPENSSL_add_all_algorithms_noconf = NULL;
#endif
#ifdef BUILDCRYPTOOPENSSL11
	_int_OPENSSL_init_crypto = NULL;
#endif
#ifdef BUILDCRYPTOOPENSSL10
	_int_ERR_load_crypto_strings = NULL;
#endif
	_int_ERR_get_error = NULL;
	_int_ERR_error_string_n = NULL;
#ifdef BUILDCRYPTOOPENSSL10
	_int_ERR_free_strings = NULL;
#endif
	_int_RAND_seed = NULL;
	_int_RAND_bytes = NULL;
	_int_EVP_get_digestbyname = NULL;
	_int_EVP_MD_size = NULL;
	_int_HMAC = NULL;
	_int_EVP_get_cipherbyname = NULL;
	_int_EVP_CIPHER_block_size = NULL;
#ifdef BUILDCRYPTOOPENSSL10
	_int_EVP_CIPHER_CTX_init = NULL;
	_int_EVP_CIPHER_CTX_cleanup = NULL;
#endif
#ifdef BUILDCRYPTOOPENSSL11
	_int_EVP_CIPHER_CTX_new = NULL;
	_int_EVP_CIPHER_CTX_free = NULL;
#endif
	_int_EVP_EncryptInit_ex = NULL;
	_int_EVP_EncryptUpdate = NULL;
	_int_EVP_EncryptFinal_ex = NULL;
	_int_EVP_DecryptInit_ex = NULL;
	_int_EVP_DecryptUpdate = NULL;
	_int_EVP_DecryptFinal_ex = NULL;
#ifdef BUILDCRYPTOOPENSSL10
	_int_EVP_cleanup = NULL;
#endif
	return;
}

static int opensslcrypto_remap_symbols(knet_handle_t knet_h)
{
	int err = 0;
	char *error = NULL;

#ifdef BUILDCRYPTOOPENSSL10
	_int_OPENSSL_add_all_algorithms_noconf = dlsym(openssl_lib, "OPENSSL_add_all_algorithms_noconf");
	if (!_int_OPENSSL_add_all_algorithms_noconf) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map OPENSSL_add_all_algorithms_noconf: %s", error);
		err = -1;
		goto out;
	}
#endif
#ifdef BUILDCRYPTOOPENSSL11
	_int_OPENSSL_init_crypto = dlsym(openssl_lib, "OPENSSL_init_crypto");
	if (!_int_OPENSSL_init_crypto) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map OPENSSL_init_crypto: %s", error);
		err = -1;
		goto out;
	}
#endif
#ifdef BUILDCRYPTOOPENSSL10
	_int_ERR_load_crypto_strings = dlsym(openssl_lib, "ERR_load_crypto_strings");
	if (!_int_ERR_load_crypto_strings) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map ERR_load_crypto_strings: %s", error);
		err = -1;
		goto out;
	}
#endif

	_int_ERR_get_error = dlsym(openssl_lib, "ERR_get_error");
	if (!_int_ERR_get_error) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map ERR_get_error: %s", error);
		err = -1;
		goto out;
	}

	_int_ERR_error_string_n = dlsym(openssl_lib, "ERR_error_string_n");
	if (!_int_ERR_error_string_n) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map ERR_error_string_n: %s", error);
		err = -1;
		goto out;
	}

#ifdef BUILDCRYPTOOPENSSL10
	_int_ERR_free_strings = dlsym(openssl_lib, "ERR_free_strings");
	if (!_int_ERR_free_strings) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map ERR_free_strings: %s", error);
		err = -1;
		goto out;
	}
#endif

	_int_RAND_seed = dlsym(openssl_lib, "RAND_seed");
	if (!_int_RAND_seed) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map RAND_seed: %s", error);
		err = -1;
		goto out;
	}

	_int_RAND_bytes = dlsym(openssl_lib, "RAND_bytes");
	if (!_int_RAND_bytes) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map RAND_bytes: %s", error);
		err = -1;
		goto out;
	}

	_int_EVP_get_digestbyname = dlsym(openssl_lib, "EVP_get_digestbyname");
	if (!_int_EVP_get_digestbyname) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_get_digestbyname: %s", error);
		err = -1;
		goto out;
	}

	_int_EVP_MD_size = dlsym(openssl_lib, "EVP_MD_size");
	if (!_int_EVP_MD_size) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_MD_size: %s", error);
		err = -1;
		goto out;
	}

	_int_HMAC = dlsym(openssl_lib, "HMAC");
	if (!_int_HMAC) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map HMAC: %s", error);
		err = -1;
		goto out;
	}

	_int_EVP_get_cipherbyname = dlsym(openssl_lib, "EVP_get_cipherbyname");
	if (!_int_EVP_get_cipherbyname) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_get_cipherbyname: %s", error);
		err = -1;
		goto out;
	}

	_int_EVP_CIPHER_block_size = dlsym(openssl_lib, "EVP_CIPHER_block_size");
	if (!_int_EVP_CIPHER_block_size) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_CIPHER_block_size: %s", error);
		err = -1;
		goto out;
	}

#ifdef BUILDCRYPTOOPENSSL10
	_int_EVP_CIPHER_CTX_init = dlsym(openssl_lib, "EVP_CIPHER_CTX_init");
	if (!_int_EVP_CIPHER_CTX_init) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_CIPHER_CTX_init: %s", error);
		err = -1;
		goto out;
	}

	_int_EVP_CIPHER_CTX_cleanup = dlsym(openssl_lib, "EVP_CIPHER_CTX_cleanup");
	if (!_int_EVP_CIPHER_CTX_cleanup) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_CIPHER_CTX_cleanup: %s", error);
		err = -1;
		goto out;
	}
#endif
#ifdef BUILDCRYPTOOPENSSL11
	_int_EVP_CIPHER_CTX_new = dlsym(openssl_lib, "EVP_CIPHER_CTX_new");
	if (!_int_EVP_CIPHER_CTX_new) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_CIPHER_CTX_new: %s", error);
		err = -1;
		goto out;
	}

	_int_EVP_CIPHER_CTX_free = dlsym(openssl_lib, "EVP_CIPHER_CTX_free");
	if (!_int_EVP_CIPHER_CTX_free) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_CIPHER_CTX_free: %s", error);
		err = -1;
		goto out;
	}
#endif

	_int_EVP_EncryptInit_ex = dlsym(openssl_lib, "EVP_EncryptInit_ex");
	if (!_int_EVP_EncryptInit_ex) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_EncryptInit_ex: %s", error);
		err = -1;
		goto out;
	}

	_int_EVP_EncryptUpdate = dlsym(openssl_lib, "EVP_EncryptUpdate");
	if (!_int_EVP_EncryptUpdate) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_EncryptUpdate: %s", error);
		err = -1;
		goto out;
	}

	_int_EVP_EncryptFinal_ex = dlsym(openssl_lib, "EVP_EncryptFinal_ex");
	if (!_int_EVP_EncryptFinal_ex) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_EncryptFinal_ex: %s", error);
		err = -1;
		goto out;
	}

	_int_EVP_DecryptInit_ex = dlsym(openssl_lib, "EVP_DecryptInit_ex");
	if (!_int_EVP_DecryptInit_ex) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_DecryptInit_ex: %s", error);
		err = -1;
		goto out;
	}

	_int_EVP_DecryptUpdate = dlsym(openssl_lib, "EVP_DecryptUpdate");
	if (!_int_EVP_DecryptUpdate) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_DecryptUpdate: %s", error);
		err = -1;
		goto out;
	}

	_int_EVP_DecryptFinal_ex = dlsym(openssl_lib, "EVP_DecryptFinal_ex");
	if (!_int_EVP_DecryptFinal_ex) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_DecryptFinal_ex: %s", error);
		err = -1;
		goto out;
	}

#ifdef BUILDCRYPTOOPENSSL10
	_int_EVP_cleanup = dlsym(openssl_lib, "EVP_cleanup");
	if (!_int_EVP_cleanup) {
		error = dlerror();
		log_err(knet_h, KNET_SUB_OPENSSLCRYPTO, "unable to map EVP_cleanup: %s", error);
		err = -1;
		goto out;
	}
#endif

out:
	if (err) {
		clean_openssl_syms();
	}

	return err;
}

void opensslcrypto_unload_lib(
	knet_handle_t knet_h)
{
	if (openssl_lib) {
#ifdef BUILDCRYPTOOPENSSL10
		if (_int_EVP_cleanup) {
			(*_int_EVP_cleanup)();
		}
		if (_int_ERR_free_strings) {
			(*_int_ERR_free_strings)();
		}
#endif
		dlclose(openssl_lib);
		openssl_lib = NULL;
		clean_openssl_syms();
	}

	return;
}

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

		if (opensslcrypto_remap_symbols(knet_h) < 0) {
			savederrno = errno;
			err = -1;
			goto out;
		}

#ifdef BUILDCRYPTOOPENSSL10
		(*_int_ERR_load_crypto_strings)();
		(*_int_OPENSSL_add_all_algorithms_noconf)();
#endif
#ifdef BUILDCRYPTOOPENSSL11
		(*_int_OPENSSL_init_crypto)(OPENSSL_INIT_ADD_ALL_CIPHERS \
					    | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
#endif
	}

out:
	if (err) {
		opensslcrypto_unload_lib(knet_h);
	}
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
